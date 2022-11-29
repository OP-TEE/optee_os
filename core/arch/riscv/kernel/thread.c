// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 * Copyright (c) 2016-2022, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020-2021, Arm Limited
 */

#include <platform_config.h>

#include <assert.h>
#include <config.h>
#include <io.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <mm/vm.h>
#include <riscv.h>
#include <trace.h>
#include <util.h>

uint32_t __nostackcheck thread_get_exceptions(void)
{
	return read_sie();
}

void __nostackcheck thread_set_exceptions(uint32_t exceptions)
{
	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	barrier();
	write_sie(exceptions);
	barrier();
}

uint32_t __nostackcheck thread_mask_exceptions(uint32_t exceptions)
{
	uint32_t state = thread_get_exceptions();

	thread_set_exceptions(state | (exceptions & THREAD_EXCP_ALL));
	return state;
}

void __nostackcheck thread_unmask_exceptions(uint32_t state)
{
	thread_set_exceptions(state & THREAD_EXCP_ALL);
}

static void thread_lazy_save_ns_vfp(void)
{
}

static void thread_lazy_restore_ns_vfp(void)
{
}

static void dump_trap_regs(struct thread_trap_regs *regs)
{
	IMSG(" x0  0x%016lx ra  0x%016lx sp  0x%016lx gp  0x%016lx",
	     0ul, regs->ra, regs->sp, regs->gp);
	IMSG(" tp  0x%016lx t0  0x%016lx t1  0x%016lx t2  0x%016lx",
	     regs->tp, regs->t0, regs->t1, regs->t2);
	IMSG(" a0  0x%016lx a1  0x%016lx a2  0x%016lx a3  0x%016lx",
	     regs->a0, regs->a1, regs->a2, regs->a3);
	IMSG(" a4  0x%016lx a5  0x%016lx a6  0x%016lx a7  0x%016lx",
	     regs->a4, regs->a5, regs->a6, regs->a7);
	IMSG(" t3  0x%016lx t4  0x%016lx t5  0x%016lx t6  0x%016lx",
	     regs->t3, regs->t4, regs->t5, regs->t6);
}

static void thread_unhandled_trap(struct thread_trap_regs *regs __unused)
{
	panic("unhandled exception");
}

static void thread_exception_handler(unsigned long cause,
				     struct thread_trap_regs *regs)
{
	switch (cause) {
	case CAUSE_MISALIGNED_FETCH:
	case CAUSE_FETCH_ACCESS:
	case CAUSE_ILLEGAL_INSTRUCTION:
	case CAUSE_BREAKPOINT:
		dump_trap_regs(regs);
		panic("debug");
		break;
	case CAUSE_MISALIGNED_LOAD:
	case CAUSE_LOAD_ACCESS:
	case CAUSE_MISALIGNED_STORE:
	case CAUSE_STORE_ACCESS:
	case CAUSE_SUPERVISOR_ECALL:
	case CAUSE_VIRTUAL_SUPERVISOR_ECALL:
	case CAUSE_MACHINE_ECALL:
	case CAUSE_FETCH_PAGE_FAULT:
	case CAUSE_LOAD_PAGE_FAULT:
	case CAUSE_STORE_PAGE_FAULT:
	case CAUSE_FETCH_GUEST_PAGE_FAULT:
	case CAUSE_LOAD_GUEST_PAGE_FAULT:
	case CAUSE_VIRTUAL_INSTRUCTION:
	case CAUSE_STORE_GUEST_PAGE_FAULT:
	case CAUSE_USER_ECALL:
		thread_unhandled_trap(regs);
		break;
	default:
		thread_unhandled_trap(regs);
	}
}

static void thread_interrupt_handler(unsigned long cause,
				     struct thread_trap_regs *regs)
{
	switch (cause) {
	case IRQ_XTIMER:
		clear_csr(CSR_XIE, CSR_XIE_TIE);
		break;
	case IRQ_XSOFT:
	case IRQ_XEXT:
		thread_unhandled_trap(regs);
		break;
	default:
		thread_unhandled_trap(regs);
	}
}

void thread_trap_handler(long cause, unsigned long epc __maybe_unused,
			 struct thread_trap_regs *regs,
			 bool core __maybe_unused)
{
	unsigned long _cause = cause & LONG_MAX;
	/*
	 * The Interrupt bit (XLEN-1) in the cause register is set
	 * if the trap was caused by an interrupt.
	 */
	if (cause < 0)
		thread_interrupt_handler(cause, regs);
	/*
	 * Otherwise, cause is never written by the implementation,
	 * though it may be explicitly written by software.
	 */
	else
		thread_exception_handler(_cause, regs);

}

static void init_regs(struct thread_ctx *thread, uint32_t a0, uint32_t a1,
		      uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
		      uint32_t a6, uint32_t a7, void *pc)
{
	assert(thread);

	thread->regs.ra = (uintptr_t)pc;

	/* Set up mstatus */
	thread->regs.status = read_csr(mstatus);
	thread->regs.status |= (MSTATUS_SPP | THREAD_EXCP_FOREIGN_INTR);

	/* Reinitialize stack pointer */
	thread->regs.sp = thread->stack_va_end;

	/*
	 * Copy arguments into context. This will make the
	 * arguments appear in a0-a7 when thread is started.
	 */
	thread->regs.a0 = a0;
	thread->regs.a1 = a1;
	thread->regs.a2 = a2;
	thread->regs.a3 = a3;
	thread->regs.a4 = a4;
	thread->regs.a5 = a5;
	thread->regs.a6 = a6;
	thread->regs.a7 = a7;

	/* Set frame pointer */
	thread->regs.fp = 0;
}

static void __thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2,
				   uint32_t a3, uint32_t a4, uint32_t a5,
				   uint32_t a6, uint32_t a7,
				   void *pc)
{
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;
	size_t n = 0;

	assert(l->curr_thread == THREAD_ID_INVALID);

	thread_lock_global();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (threads[n].state == THREAD_STATE_FREE) {
			threads[n].state = THREAD_STATE_ACTIVE;
			found_thread = true;
			break;
		}
	}

	thread_unlock_global();

	if (!found_thread)
		return;

	l->curr_thread = n;

	threads[n].flags = 0;
	init_regs(threads + n, a0, a1, a2, a3, a4, a5, a6, a7, pc);

	thread_lazy_save_ns_vfp();

	l->flags &= ~THREAD_CLF_TMP;
	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5)
{
	__thread_alloc_and_run(a0, a1, a2, a3, a4, a5, 0, 0,
			       thread_std_smc_entry);
}

static void copy_a0_to_a3(struct thread_ctx_regs *regs, uint32_t a0,
			  uint32_t a1, uint32_t a2, uint32_t a3)
{
	regs->a0 = a0;
	regs->a1 = a1;
	regs->a2 = a2;
	regs->a3 = a3;
}

static bool is_from_user(unsigned long status)
{
	return (status & MSTATUS_SPP);
}

#ifdef CFG_SYSCALL_FTRACE
static void __noprof ftrace_suspend(void)
{
	struct ts_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s && s->fbuf)
		s->fbuf->syscall_trace_suspended = true;
}

static void __noprof ftrace_resume(void)
{
	struct ts_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s && s->fbuf)
		s->fbuf->syscall_trace_suspended = false;
}
#else
static void __maybe_unused __noprof ftrace_suspend(void)
{
}

static void __noprof ftrace_resume(void)
{
}
#endif

static bool is_user_mode(struct thread_ctx_regs *regs)
{
	return is_from_user((uint32_t)regs->status);
}

void thread_resume_from_rpc(uint32_t thread_id, uint32_t a0, uint32_t a1,
			    uint32_t a2, uint32_t a3)
{
	size_t n = thread_id;
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == THREAD_ID_INVALID);

	thread_lock_global();

	if (n < CFG_NUM_THREADS && threads[n].state == THREAD_STATE_SUSPENDED) {
		threads[n].state = THREAD_STATE_ACTIVE;
		found_thread = true;
	}

	thread_unlock_global();

	if (!found_thread)
		return;

	l->curr_thread = n;

	if (threads[n].have_user_map) {
		core_mmu_set_user_map(&threads[n].user_map);
		if (threads[n].flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR)
			tee_ta_ftrace_update_times_resume();
	}

	if (is_user_mode(&threads[n].regs))
		tee_ta_update_session_utime_resume();

	/*
	 * Return from RPC to request service of a foreign interrupt must not
	 * get parameters from non-secure world.
	 */
	if (threads[n].flags & THREAD_FLAGS_COPY_ARGS_ON_RETURN) {
		copy_a0_to_a3(&threads[n].regs, a0, a1, a2, a3);
		threads[n].flags &= ~THREAD_FLAGS_COPY_ARGS_ON_RETURN;
	}

	thread_lazy_save_ns_vfp();

	if (threads[n].have_user_map)
		ftrace_resume();

	l->flags &= ~THREAD_CLF_TMP;
	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

void thread_state_free(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	thread_lazy_restore_ns_vfp();
	tee_pager_release_phys((void *)(threads[ct].stack_va_end -
				STACK_THREAD_SIZE), STACK_THREAD_SIZE);

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = THREAD_ID_INVALID;

	if (IS_ENABLED(CFG_VIRTUALIZATION))
		virt_unset_guest();
	thread_unlock_global();
}

bool thread_init_stack(uint32_t thread_id, vaddr_t sp)
{
	if (thread_id >= CFG_NUM_THREADS)
		return false;
	threads[thread_id].stack_va_end = sp;
	return true;
}

static void init_user_kcode(void)
{
}

void thread_init_primary(void)
{
	/* Initialize canaries around the stacks */
	thread_init_canaries();

	init_user_kcode();
}

static vaddr_t get_trap_vect(void)
{
	return (vaddr_t)thread_trap_vect;
}

void thread_init_tvec(void)
{
	unsigned long tvec = (unsigned long)get_trap_vect();

#ifdef RISCV_M_MODE
	write_mtvec(tvec);
	assert(read_mtvec() == tvec);
#else /* RISCV_S_MODE */
	write_stvec(tvec);
	assert(read_stvec() == tvec);
#endif
}

void thread_init_per_cpu(void)
{
	thread_init_tvec();
}

static void set_ctx_regs(struct thread_ctx_regs *regs, unsigned long a0,
			 unsigned long a1, unsigned long a2, unsigned long a3,
			 unsigned long user_sp, unsigned long entry_func,
			 uint32_t status,
			 struct thread_pauth_keys *keys __unused)
{
	/*
	 * First clear all registers to avoid leaking information from
	 * other TAs or even the Core itself.
	 */
	*regs = (struct thread_ctx_regs){ };
	regs->a0 = a0;
	regs->a1 = a1;
	regs->a2 = a2;
	regs->a3 = a3;
	regs->sp = user_sp;
	regs->ra = entry_func;
	regs->status = status;

	/* Set frame pointer (user stack can't be unwound past this point) */
	regs->fp = 0;
}

uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
				unsigned long a2, unsigned long a3,
				unsigned long user_sp,
				unsigned long entry_func,
				bool is_32bit __unused,
				uint32_t *exit_status0,
				uint32_t *exit_status1)
{
	uint32_t status = 0;
	uint32_t exceptions = 0;
	uint32_t rc = 0;
	struct thread_ctx_regs *regs = NULL;

	tee_ta_update_session_utime_resume();

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	regs = thread_get_ctx_regs();
	set_ctx_regs(regs, a0, a1, a2, a3, user_sp, entry_func, status, NULL);
	rc = __thread_enter_user_mode(regs, exit_status0, exit_status1);
	thread_unmask_exceptions(exceptions);
	return rc;
}

struct mobj *thread_rpc_alloc_payload(size_t size __unused)
{
	return NULL;
}

void thread_rpc_free_payload(struct mobj *mobj __unused)
{
}

struct mobj *thread_rpc_alloc_kernel_payload(size_t size __unused)
{
	return NULL;
}

void thread_rpc_free_kernel_payload(struct mobj *mobj __unused)
{
}

struct mobj *thread_rpc_alloc_global_payload(size_t size __unused)
{
	return NULL;
}

void thread_rpc_free_global_payload(struct mobj *mobj __unused)
{
}

uint32_t thread_rpc_cmd(uint32_t cmd __unused, size_t num_params __unused,
			struct thread_param *params __unused)
{
	return 0;
}
