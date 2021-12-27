// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <platform_config.h>

#include <riscv.h>
#include <assert.h>
#include <config.h>
#include <keep.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <trace.h>
#include <util.h>


uint32_t __nostackcheck thread_get_exceptions(void)
{
	return read_csr(mie);
}

void __nostackcheck thread_set_exceptions(uint32_t exceptions)
{
	write_csr(mie, exceptions);
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


static void thread_unhandled_trap(struct thread_trap_frame *frame __unused)
{
	panic("unhandled exception");
}

static void dump_trap_frame(struct thread_trap_frame *frame)
{
	IMSG(" x0  0x%016lx ra  0x%016lx sp  0x%016lx gp  0x%016lx",
	     0ul, frame->ra, frame->sp, frame->gp);
	IMSG(" tp  0x%016lx t0  0x%016lx t1  0x%016lx t2  0x%016lx",
	     frame->tp, frame->t0, frame->t1, frame->t2);
	IMSG(" a0  0x%016lx a1  0x%016lx a2  0x%016lx a3  0x%016lx",
	     frame->a0, frame->a1, frame->a2, frame->a3);
	IMSG(" a4  0x%016lx a5  0x%016lx a6  0x%016lx a7  0x%016lx",
	     frame->a4, frame->a5, frame->a6, frame->a7);
	IMSG(" t3  0x%016lx t4  0x%016lx t5  0x%016lx t6  0x%016lx",
	     frame->t3, frame->t4, frame->t5, frame->t6);
}

static void thread_exception_handler(unsigned long cause,
				     struct thread_trap_frame *frame)
{
	switch (cause) {
	case CAUSE_MISALIGNED_FETCH:
	case CAUSE_FETCH_ACCESS:
	case CAUSE_ILLEGAL_INSTRUCTION:
	case CAUSE_BREAKPOINT:
		dump_trap_frame(frame);
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
		thread_unhandled_trap(frame);
		break;
	default:
		thread_unhandled_trap(frame);
	}
}

static void thread_interrupt_handler(unsigned long cause,
				     struct thread_trap_frame *frame)
{
	switch (cause) {
	case IRQ_M_TIMER:
		clear_csr(mie, MIP_MTIP);
		break;
	case IRQ_M_SOFT:
	case IRQ_M_EXT:
		thread_unhandled_trap(frame);
		break;
	default:
		thread_unhandled_trap(frame);
	}
}

void thread_trap_handler(long mcause, unsigned long epc __maybe_unused,
			 struct thread_trap_frame *frame,
			 bool core __maybe_unused)
{
	unsigned long cause = mcause & LONG_MAX;
	/*
	 * The Interrupt bit (XLEN-1) in the mcause register is set
	 * if the trap was caused by an interrupt.
	 */
	if (mcause < 0)
		thread_interrupt_handler(cause, frame);
	/*
	 * Otherwise, mcause is never written by the implementation,
	 * though it may be explicitly written by software.
	 */
	else
		thread_exception_handler(cause, frame);
}

static vaddr_t get_trap_vect(void)
{
	return (vaddr_t)thread_trap_vect;
}

void thread_init_tvec(void)
{
	unsigned long tvec = (unsigned long) get_trap_vect();

	write_mtvec(tvec);
	assert(read_mtvec() == tvec);
}

void thread_init_per_cpu(void)
{
	thread_init_tvec();
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
static void __noprof ftrace_suspend(void)
{
}

static void __noprof ftrace_resume(void)
{
}
#endif

static bool is_from_user(unsigned long status)
{
	return (status & MSTATUS_SPP);
}

static void copy_a0_to_a3(struct thread_ctx_regs *regs, uint32_t a0,
			  uint32_t a1, uint32_t a2, uint32_t a3)
{
	/*
	 * Update returned values from RPC, values will appear in
	 * x0-x3 when thread is resumed.
	 */
	regs->a0 = a0;
	regs->a1 = a1;
	regs->a2 = a2;
	regs->a3 = a3;
}

static bool is_user_mode(struct thread_ctx_regs *regs)
{
	return is_from_user(regs->status);
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

	if (threads[n].have_user_map)
		ftrace_resume();

	l->flags &= ~THREAD_CLF_TMP;
	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

static void set_ctx_regs(struct thread_ctx_regs *regs, unsigned long a0,
			 unsigned long a1, unsigned long a2, unsigned long a3,
			 unsigned long user_sp, unsigned long entry_func,
			 unsigned long status)
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
				unsigned long user_sp, unsigned long entry_func,
				bool is_32bit __unused, uint32_t *exit_status0,
				uint32_t *exit_status1)
{
	unsigned long status = 0;
	uint32_t masked_exceptions = 0;
	uint32_t rc = 0;
	struct thread_ctx_regs *regs = NULL;

	tee_ta_update_session_utime_resume();

	masked_exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	regs = thread_get_ctx_regs();
	set_ctx_regs(regs, a0, a1, a2, a3, user_sp, entry_func, status);
	rc = __thread_enter_user_mode(regs, exit_status0, exit_status1);
	thread_unmask_exceptions(masked_exceptions);

	return rc;
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
	size_t n;
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

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
