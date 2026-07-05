// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 * Copyright (c) 2016-2022, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020-2021, Arm Limited
 */

#include <platform_config.h>

#include <asan.h>
#include <assert.h>
#include <config.h>
#include <io.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
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
#include <kernel/user_mode_ctx.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/vm.h>
#include <riscv.h>
#include <trace.h>
#include <util.h>
#if defined(CFG_WITH_VFP)
#include <riscv_vector.h>
#endif

/*
 * This function is called as a guard after each ABI call which is not
 * supposed to return.
 */
void __noreturn __panic_at_abi_return(void)
{
	panic();
}

/* This function returns current masked exception bits. */
uint32_t __nostackcheck thread_get_exceptions(void)
{
	uint32_t xie = read_csr(CSR_XIE) & THREAD_EXCP_ALL;

	return xie ^ THREAD_EXCP_ALL;
}

void __nostackcheck thread_set_exceptions(uint32_t exceptions)
{
	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	/*
	 * In ARM, the bits in DAIF register are used to mask the exceptions.
	 * While in RISC-V, the bits in CSR XIE are used to enable(unmask)
	 * corresponding interrupt sources. To not modify the function of
	 * thread_set_exceptions(), we should "invert" the bits in "exceptions".
	 * The corresponding bits in "exceptions" will be inverted so they will
	 * be cleared when we write the final value into CSR XIE. So that we
	 * can mask those exceptions.
	 */
	exceptions &= THREAD_EXCP_ALL;
	exceptions ^= THREAD_EXCP_ALL;

	barrier();
	write_csr(CSR_XIE, exceptions);
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

#if defined(CFG_WITH_VFP)
static unsigned long xstatus_set_vs(unsigned long xstatus,
				    unsigned long vs)
{
#ifdef RV64
	return set_field_u64(xstatus, CSR_XSTATUS_VS_MASK, vs);
#else
	return set_field_u32(xstatus, CSR_XSTATUS_VS_MASK, vs);
#endif
}

static void riscv_vector_disable(void)
{
	unsigned long xstatus = read_csr(CSR_XSTATUS);

	xstatus = xstatus_set_vs(xstatus, CSR_XSTATUS_VS_OFF);
	write_csr(CSR_XSTATUS, xstatus);
}

static void thread_eager_save_ns_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_NS);

	/*
	 * thread_save_vector_state() must temporarily enable VS and restore the
	 * original xstatus before returning.
	 */
	assert(thr->vfp_state.ns);
	thread_save_vector_state(thr->vfp_state.ns);

	thr->vfp_state.ns_valid = true;

	/*
	 * The normal-world state is now held in memory, and no context owns
	 * the physical vector registers.
	 */
	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NONE;

	riscv_vector_disable();
}

static void thread_eager_restore_ns_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_NONE);
	assert(thr->vfp_state.ns);

	if (thr->vfp_state.ns_valid)
		thread_restore_vector_state(thr->vfp_state.ns);

	/*
	 * If ns_valid is false, no secure vector context has replaced the
	 * incoming normal-world vector registers, so leave the hardware
	 * registers unchanged.
	 */
	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NS;
}
#if 0
static void thread_eager_restore_ns_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	/*
	 * Any user or kernel vector context must have been eagerly saved before
	 * restoring the normal-world registers.
	 */
	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_NONE);
	assert(thr->vfp_state.ns_valid);
	assert(thr->vfp_state.ns);

	/*
	 * thread_restore_vector_state() temporarily enables VS and restores
	 * the original xstatus before returning.
	 */
	if (thr->vfp_state.ns_valid)
		thread_restore_vector_state(thr->vfp_state.ns);

	/*
	 * The physical vector registers now contain normal-world state.
	 */
	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NS;
}
#endif
#endif /* CFG_WITH_VFP */

static void setup_unwind_user_mode(struct thread_scall_regs *regs)
{
	regs->epc = (uintptr_t)thread_unwind_user_mode;
	regs->status = xstatus_for_xret(true, PRV_S);
	regs->ie = 0;
	/*
	 * We are going to exit user mode. The stack pointer must be set as the
	 * original value it had before allocating space of scall "regs" and
	 * calling thread_scall_handler(). Thus, we can simply set stack pointer
	 * as (regs + 1) value.
	 */
	regs->sp = (uintptr_t)(regs + 1);
}

#if defined(CFG_WITH_VFP)
static struct riscv_vector_state *alloc_vector_state(void)
{
	struct riscv_vector_state *state = NULL;
	size_t size = riscv_vector_state_size();

	state = calloc(1, size);
	if (!state)
		return NULL;

	return state;
}

int thread_init_vector_context(struct thread_vfp_state *vfp)
{
	assert(vfp);

	memset(vfp, 0, sizeof(*vfp));

	vfp->ns = alloc_vector_state();
	if (!vfp->ns)
		return -1;

	vfp->sec = alloc_vector_state();
	if (!vfp->sec) {
		free(vfp->ns);
		vfp->ns = NULL;
		return -1;
	}

	vfp->owner = RISCV_VECTOR_OWNER_NONE;

	return 0;
}

void thread_free_vector_context(struct thread_vfp_state *vfp)
{
	if (!vfp)
		return;

	free(vfp->ns);
	free(vfp->sec);

	vfp->ns = NULL;
	vfp->sec = NULL;
	vfp->uvfp = NULL;
	vfp->owner = RISCV_VECTOR_OWNER_NONE;
	vfp->ns_valid = false;
	vfp->sec_valid = false;
}
#endif /* CFG_WITH_VFP */

static void thread_unhandled_trap(struct thread_ctx_regs *regs __unused,
				  unsigned long cause __unused)
{
	DMSG("Unhandled trap xepc:0x%016lx xcause:0x%016lx xtval:0x%016lx",
	     read_csr(CSR_XEPC), read_csr(CSR_XCAUSE), read_csr(CSR_XTVAL));
	panic();
}

void thread_scall_handler(struct thread_scall_regs *regs)
{
	struct ts_session *sess = NULL;
	uint32_t state = 0;

	/* Enable native interrupts */
	state = thread_get_exceptions();
	thread_unmask_exceptions(state & ~THREAD_EXCP_NATIVE_INTR);

#if defined(CFG_WITH_VFP)
	/*
	 * The syscall entered from user mode. Save the user TA vector
	 * registers before executing secure kernel syscall code.
	 */
	thread_user_save_vfp();
#endif

	sess = ts_get_current_session();

	/* Restore foreign interrupts which are disabled on exception entry */
	thread_restore_foreign_intr();

	assert(sess && sess->handle_scall);

	if (sess->handle_scall(regs)) {
		/*
		 * We are returning to the instruction following the ecall in
		 * user mode. Restore the user TA vector context first.
		 */
#if defined(CFG_WITH_VFP)
		thread_user_restore_vfp();
#endif
		regs->epc += 4;
	} else {
		/* We are returning from __thread_enter_user_mode() */
		setup_unwind_user_mode(regs);
	}
}

static void thread_irq_handler(void)
{
	interrupt_main_handler();
}

void thread_native_interrupt_handler(struct thread_ctx_regs *regs,
				     unsigned long cause)
{
	switch (cause & LONG_MAX) {
	case IRQ_XTIMER:
		clear_csr(CSR_XIE, CSR_XIE_TIE);
		break;
	case IRQ_XSOFT:
		thread_unhandled_trap(regs, cause);
		break;
	case IRQ_XEXT:
		thread_irq_handler();
		break;
	default:
		thread_unhandled_trap(regs, cause);
	}
}

unsigned long xstatus_for_xret(uint8_t pie, uint8_t pp)
{
	unsigned long xstatus = read_csr(CSR_XSTATUS);

	assert(pp == PRV_M || pp == PRV_S || pp == PRV_U);

#ifdef RV32
	xstatus = set_field_u32(xstatus, CSR_XSTATUS_IE, 0);
	xstatus = set_field_u32(xstatus, CSR_XSTATUS_PIE, pie);
	xstatus = set_field_u32(xstatus, CSR_XSTATUS_SPP, pp);
#else	/* RV64 */
	xstatus = set_field_u64(xstatus, CSR_XSTATUS_IE, 0);
	xstatus = set_field_u64(xstatus, CSR_XSTATUS_PIE, pie);
	xstatus = set_field_u64(xstatus, CSR_XSTATUS_SPP, pp);
#endif

	return xstatus;
}

static void init_regs(struct thread_ctx *thread, uint32_t a0, uint32_t a1,
		      uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
		      uint32_t a6, uint32_t a7, void *pc)
{
	memset(&thread->regs, 0, sizeof(thread->regs));

	thread->regs.epc = (uintptr_t)pc;

	/* Set up xstatus */
	thread->regs.status = xstatus_for_xret(true, PRV_S);

	/* Enable native interrupt */
	thread->regs.ie = THREAD_EXCP_NATIVE_INTR;

	/* Reinitialize stack pointer */
	thread->regs.sp = thread->stack_va_end;

	/* Set up GP and TP */
	thread->regs.gp = read_gp();
	thread->regs.tp = read_tp();

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
}

static void thread_ensure_vector_context(struct thread_ctx *thr)
{
	if (thr->vfp_state.ns && thr->vfp_state.sec)
		return;

	if (thread_init_vector_context(&thr->vfp_state))
		panic("Failed to allocate RISC-V vector contexts");
}

static void __thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2,
				   uint32_t a3, uint32_t a4, uint32_t a5,
				   uint32_t a6, uint32_t a7,
				   void *pc)
{
	struct thread_core_local *l = thread_get_core_local();
#if defined(CFG_WITH_VFP)
	struct thread_ctx *thr = NULL;
#endif
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
#if defined(CFG_WITH_VFP)
	if (thread_init_vector_context(&threads[n].vfp_state))
		panic("Failed to allocate RISC-V vector contexts");
	thr = threads + n;
#endif
	threads[n].flags = 0;

#if defined(CFG_WITH_VFP)
	/*
	 * The hardware vector registers initially belong to the context that
	 * entered OP-TEE.
	 */
	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NS;
#endif

	init_regs(threads + n, a0, a1, a2, a3, a4, a5, a6, a7, pc);

#if defined(CFG_WITH_VFP)
	/*
	 * Eagerly save the incoming normal-world vector context and release
	 * hardware vector ownership before running secure-kernel code.
	 */
	thread_eager_save_ns_vfp();
#endif

	l->flags &= ~THREAD_CLF_TMP;

	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5)
{
	__thread_alloc_and_run(a0, a1, a2, a3, a4, a5, 0, 0,
			       thread_std_abi_entry);
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
	return (status & CSR_XSTATUS_SPP) == 0;
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

vaddr_t thread_get_saved_thread_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);
	return threads[ct].kern_sp;
}

uint32_t thread_get_hartid(void)
{
	size_t hartidx = get_core_pos();

	return thread_core_local[hartidx].hart_id;
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
	 * We may resume thread at another hart, so we need to re-assign value
	 * of tp to be current hart's thread_core_local.
	 */
	if (!is_user_mode(&threads[n].regs))
		threads[n].regs.tp = read_tp();

	/*
	 * Return from RPC to request service of a foreign interrupt must not
	 * get parameters from non-secure world.
	 */
	if (threads[n].flags & THREAD_FLAGS_COPY_ARGS_ON_RETURN) {
		copy_a0_to_a3(&threads[n].regs, a0, a1, a2, a3);
		threads[n].flags &= ~THREAD_FLAGS_COPY_ARGS_ON_RETURN;
	}

#if defined(CFG_WITH_VFP)
	thread_eager_save_ns_vfp();
#endif

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

#if defined(CFG_WITH_VFP)
	thread_eager_restore_ns_vfp();
#endif

	thread_lock_global();

#if defined(CFG_WITH_VFP)
	thread_free_vector_context(&threads[ct].vfp_state);
#endif

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = THREAD_ID_INVALID;

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
		virt_unset_guest();
	thread_unlock_global();
}

int thread_state_suspend(uint32_t flags, unsigned long status, vaddr_t pc)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	if (core_mmu_user_mapping_is_active())
		ftrace_suspend();

	thread_check_canaries();

	if (is_from_user(status)) {
#if defined(CFG_WITH_VFP)
		/*
		 * Eagerly save user-TA vector registers before restoring the
		 * normal-world vector context.
		 */
 		thread_user_save_vfp();
#endif
		tee_ta_update_session_utime_suspend();
		tee_ta_gprof_sample_pc(pc);
	}

#if defined(CFG_WITH_VFP)
	thread_eager_restore_ns_vfp();
#endif

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].flags |= flags;
	threads[ct].regs.status = status;
	threads[ct].regs.epc = pc;
	threads[ct].state = THREAD_STATE_SUSPENDED;

	threads[ct].have_user_map = core_mmu_user_mapping_is_active();
	if (threads[ct].have_user_map) {
		if (threads[ct].flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR)
			tee_ta_ftrace_update_times_suspend();
		core_mmu_get_user_map(&threads[ct].user_map);
		core_mmu_set_user_map(NULL);
	}

	l->curr_thread = THREAD_ID_INVALID;

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
		virt_unset_guest();

	thread_unlock_global();

	return ct;
}

static void init_user_kcode(void)
{
}

void thread_init_primary(void)
{
	init_user_kcode();
}

static vaddr_t get_trap_vect(void)
{
	return (vaddr_t)thread_trap_vect;
}

void thread_init_tvec(void)
{
	unsigned long tvec = (unsigned long)get_trap_vect();

	write_csr(CSR_XTVEC, tvec);
	assert(read_csr(CSR_XTVEC) == tvec);
}

void thread_init_per_cpu(void)
{
	thread_init_tvec();
	/*
	 * We may receive traps from now, therefore, zeroize xSCRATCH such
	 * that thread_trap_vect() can distinguish between user traps
	 * and kernel traps.
	 */
	write_csr(CSR_XSCRATCH, 0);
#ifndef CFG_PAN
	/*
	 * Allow access to user pages. When CFG_PAN is enabled, the SUM bit will
	 * be set and clear at runtime when necessary.
	 */
	set_csr(CSR_XSTATUS, CSR_XSTATUS_SUM);
#endif
}

static void set_ctx_regs(struct thread_ctx_regs *regs, unsigned long a0,
			 unsigned long a1, unsigned long a2, unsigned long a3,
			 unsigned long user_sp, unsigned long entry_func,
			 unsigned long status, unsigned long ie,
			 struct thread_pauth_keys *keys __unused)
{
	*regs = (struct thread_ctx_regs){
		.a0 = a0,
		.a1 = a1,
		.a2 = a2,
		.a3 = a3,
		.s0 = 0,
		.sp = user_sp,
		.epc = entry_func,
		.status = status,
		.ie = ie,
	};
}

uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
				unsigned long a2, unsigned long a3,
				unsigned long user_sp,
				unsigned long entry_func,
				bool is_32bit __unused,
				uint32_t *exit_status0,
				uint32_t *exit_status1)
{
	unsigned long status = 0;
	unsigned long ie = 0;
	uint32_t exceptions = 0;
	uint32_t rc = 0;
	struct thread_ctx_regs *regs = NULL;

#if defined(CFG_WITH_VFP)
	struct thread_ctx *thr = threads + thread_get_id();
	struct ts_session *s = NULL;
	struct user_mode_ctx *uctx = NULL;
#endif

	tee_ta_update_session_utime_resume();

	/* Read current interrupt masks */
	ie = read_csr(CSR_XIE);

	/*
	 * Mask all exceptions, the CSR_XSTATUS.IE will be set from
	 * setup_unwind_user_mode() after exiting.
	 */
	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
#if defined(CFG_WITH_VFP)
	/*
	 * Select the user-TA vector state associated with the current session.
	 * This must happen after exceptions have been masked.
	 */
	s = ts_get_current_session();
	assert(s);
	assert(s->ctx);

	uctx = to_user_mode_ctx(s->ctx);
	assert(uctx);

	/*
	 * Kernel or normal-world vector state must already have been saved
	 * before entering user mode.
	 */
	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_NONE);

	thr->vfp_state.uvfp = &uctx->vfp;

	/*
	 * Eagerly restore the TA vector context and give the hardware vector
	 * registers to the user TA.
	 */
	thread_user_restore_vfp();
#endif
	regs = thread_get_ctx_regs();
	status = xstatus_for_xret(true, PRV_U);
	set_ctx_regs(regs, a0, a1, a2, a3, user_sp, entry_func, status, ie,
		     NULL);
	rc = __thread_enter_user_mode(regs, exit_status0, exit_status1);
#if defined(CFG_WITH_VFP)
	/*
	 * __thread_enter_user_mode() has returned from user mode. Eagerly
	 * save the TA vector registers before unmasking exceptions or allowing
	 * secure-kernel code to use vector.
	 *
	 * thread_user_save_vfp() must tolerate owner == NONE because the
	 * context may already have been saved by thread_state_suspend().
	 */
	thread_user_save_vfp();
#endif
	thread_unmask_exceptions(exceptions);

	return rc;
}

void __thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS])
{
	thread_rpc_xstatus(rv, xstatus_for_xret(false, PRV_S));
}

#if defined(CFG_WITH_VFP)

#ifdef RV64
#define STATE_TOKEN_VEC		SHIFT_U64(1, 0)
#else
#define STATE_TOKEN_VEC		SHIFT_U32(1, 0)
#endif

static unsigned long xstatus_get_vs(unsigned long xstatus)
{
	return (xstatus & CSR_XSTATUS_VS_MASK) >>
	       CSR_XSTATUS_VS_BIT;
}

static bool riscv_vector_is_enabled(void)
{
	return xstatus_get_vs(read_csr(CSR_XSTATUS)) !=
	       CSR_XSTATUS_VS_OFF;
}

static void riscv_vector_enable_initial(void)
{
	unsigned long xstatus = read_csr(CSR_XSTATUS);

	xstatus = xstatus_set_vs(xstatus, CSR_XSTATUS_VS_INITIAL);
	write_csr(CSR_XSTATUS, xstatus);
}

static void riscv_vector_enable_clean(void)
{
	unsigned long xstatus = read_csr(CSR_XSTATUS);

	xstatus = xstatus_set_vs(xstatus, CSR_XSTATUS_VS_CLEAN);
	write_csr(CSR_XSTATUS, xstatus);
}

void thread_save_vector_state(struct riscv_vector_state *ctx)
{
	assert(ctx);
	riscv_vector_save(ctx);
}

void thread_restore_vector_state(struct riscv_vector_state *ctx)
{
	riscv_vector_restore(ctx);
}

static void save_active_vector_context(struct thread_ctx *thr)
{
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	switch (thr->vfp_state.owner) {
	case RISCV_VECTOR_OWNER_NONE:
		return;

	case RISCV_VECTOR_OWNER_NS:
		assert(thr->vfp_state.ns);

		thread_save_vector_state(thr->vfp_state.ns);
		thr->vfp_state.ns_valid = true;
		break;

	case RISCV_VECTOR_OWNER_KERNEL:
		assert(thr->vfp_state.sec);

		thread_save_vector_state(thr->vfp_state.sec);
		thr->vfp_state.sec_valid = true;
		break;

	case RISCV_VECTOR_OWNER_USER:
		assert(tuv);
		assert(tuv->vector_state);

		thread_save_vector_state(tuv->vector_state);
		tuv->valid = true;
		break;

	default:
		panic();
	}

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NONE;
	riscv_vector_disable();
}

uint32_t thread_kernel_enable_vfp(void)
{
	uint32_t exceptions = 0;
	struct thread_ctx *thr = NULL;

	/*
	 * Keep foreign interrupts masked for the complete interval during
	 * which the kernel owns and uses the vector registers.
	 */
	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	thr = threads + thread_get_id();

	/*
	 * This interface is not recursive. A second kernel enable without
	 * a matching disable indicates incorrect use.
	 */
	assert(thr->vfp_state.owner != RISCV_VECTOR_OWNER_KERNEL);

	/*
	 * Eagerly save whichever non-kernel context is still resident in
	 * the hardware vector registers.
	 */
	save_active_vector_context(thr);

	assert(thr->vfp_state.sec);

	/*
	 * VS=Initial enables vector instructions and represents a newly
	 * activated vector context.
	 */
	riscv_vector_enable_initial();

	/*
	 * Restore persistent secure-kernel vector state, if one exists.
	 */
	if (thr->vfp_state.sec_valid) {
		thread_restore_vector_state(thr->vfp_state.sec);
		riscv_vector_enable_clean();
	}

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_KERNEL;

	/*
	 * Exception mask is restored by thread_kernel_disable_vfp().
	 */
	return exceptions;
}

void thread_kernel_disable_vfp(uint32_t state)
{
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t exceptions = 0;

	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_KERNEL);
	assert(thr->vfp_state.sec);
	assert(riscv_vector_is_enabled());

	/*
	 * Eagerly preserve the secure-kernel vector state.
	 */
	thread_save_vector_state(thr->vfp_state.sec);
	thr->vfp_state.sec_valid = true;

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NONE;
	riscv_vector_disable();

	/*
	 * Restore only the foreign-interrupt bit from the state returned by
	 * thread_kernel_enable_vfp(). Preserve all other exception bits.
	 */
	exceptions = thread_get_exceptions();

	assert(exceptions & THREAD_EXCP_FOREIGN_INTR);

	exceptions &= ~THREAD_EXCP_FOREIGN_INTR;
	exceptions |= state & THREAD_EXCP_FOREIGN_INTR;

	thread_set_exceptions(exceptions);
}

void thread_kernel_save_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_KERNEL);
	assert(thr->vfp_state.sec);
	assert(riscv_vector_is_enabled());

	thread_save_vector_state(thr->vfp_state.sec);
	thr->vfp_state.sec_valid = true;

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NONE;
	riscv_vector_disable();

	thread_set_exceptions(exceptions);
}

void thread_kernel_restore_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_NONE);
	assert(thr->vfp_state.sec);

	riscv_vector_enable_initial();

	if (thr->vfp_state.sec_valid) {
		thread_restore_vector_state(thr->vfp_state.sec);
		riscv_vector_enable_clean();
	}

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_KERNEL;

	thread_set_exceptions(exceptions);
}

static bool alloc_user_vector_state(struct thread_user_vfp_state *tuv)
{
	assert(tuv);

	if (tuv->vector_state)
		return true;

	tuv->vector_state = alloc_vector_state();
	if (!tuv->vector_state)
		return false;

	tuv->valid = false;
	return true;
}

void thread_user_enable_vfp(struct thread_user_vfp_state *tuv)
{
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t exceptions = 0;

	assert(tuv);

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	if (!alloc_user_vector_state(tuv))
		panic("Failed to allocate user RISC-V vector context");

	if (thr->vfp_state.owner != RISCV_VECTOR_OWNER_NONE)
		save_active_vector_context(thr);

	riscv_vector_enable_initial();

	/*
	 * The allocation is zero-initialized, so also restore it for a new
	 * context to prevent vector-register contents leaking between TAs.
	 */
	thread_restore_vector_state(tuv->vector_state);

	if (tuv->valid)
		riscv_vector_enable_clean();

	thr->vfp_state.uvfp = tuv;
	thr->vfp_state.owner = RISCV_VECTOR_OWNER_USER;

	thread_set_exceptions(exceptions);
}

void thread_user_save_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	if (thr->vfp_state.owner == RISCV_VECTOR_OWNER_NONE)
		return;

	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_USER);
	assert(tuv);
	assert(tuv->vector_state);

	thread_save_vector_state(tuv->vector_state);
	tuv->valid = true;

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NONE;
	riscv_vector_disable();
}

void thread_user_restore_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;
	uint32_t exceptions = 0;

	assert(tuv);

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	if (!alloc_user_vector_state(tuv))
		panic("Failed to allocate user RISC-V vector context");

	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_NONE);

	riscv_vector_enable_initial();

	if (tuv->valid) {
		thread_restore_vector_state(tuv->vector_state);
		riscv_vector_enable_clean();
	} else {
		/*
		 * The allocation was zeroed by calloc(). Restore it to prevent
		 * vector-register contents leaking from another context.
		 */
		thread_restore_vector_state(tuv->vector_state);
	}

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_USER;

	thread_set_exceptions(exceptions);
}
#endif

#ifdef CFG_WITH_VFP
void thread_user_clear_vfp(struct user_mode_ctx *uctx)
{
	struct thread_user_vfp_state *tuv = &uctx->vfp;
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	/*
	 * Disable the resident user context only when it belongs to the
	 * user context being destroyed.
	 */
	if (thr->vfp_state.owner == RISCV_VECTOR_OWNER_USER &&
	    thr->vfp_state.uvfp == tuv) {
		thr->vfp_state.owner = RISCV_VECTOR_OWNER_NONE;
		riscv_vector_disable();
	}

	if (thr->vfp_state.uvfp == tuv)
		thr->vfp_state.uvfp = NULL;

	free(tuv->vector_state);
	tuv->vector_state = NULL;
	tuv->valid = false;

	thread_set_exceptions(exceptions);
}

#if defined(CFG_WITH_VFP)
void thread_ns_save_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	assert(thr->vfp_state.owner == RISCV_VECTOR_OWNER_NS);
	assert(thr->vfp_state.ns);

	thread_save_vector_state(thr->vfp_state.ns);
	thr->vfp_state.ns_valid = true;

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NONE;
	riscv_vector_disable();

	thread_set_exceptions(exceptions);
}

void thread_ns_restore_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	uint32_t exceptions = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);

	if (thr->vfp_state.owner != RISCV_VECTOR_OWNER_NONE)
		save_active_vector_context(thr);

	assert(thr->vfp_state.ns);
	riscv_vector_enable_initial();

	if (thr->vfp_state.ns_valid) {
		thread_restore_vector_state(thr->vfp_state.ns);
		riscv_vector_enable_clean();
	}

	thr->vfp_state.owner = RISCV_VECTOR_OWNER_NS;

	thread_set_exceptions(exceptions);
}
#endif /* CFG_WITH_VFP && */

