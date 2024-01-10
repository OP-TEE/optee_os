// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2022, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020-2021, Arm Limited
 */

#include <platform_config.h>

#include <arm.h>
#include <assert.h>
#include <config.h>
#include <io.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/linker.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/spmc_sp_handler.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <kernel/user_access.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <smccc.h>
#include <sm/sm.h>
#include <trace.h>
#include <util.h>

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
static vaddr_t thread_user_kcode_va __nex_bss;
long thread_user_kcode_offset __nex_bss;
static size_t thread_user_kcode_size __nex_bss;
#endif

#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) && \
	defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC) && defined(ARM64)
long thread_user_kdata_sp_offset __nex_bss;
static uint8_t thread_user_kdata_page[
	ROUNDUP(sizeof(struct thread_core_local) * CFG_TEE_CORE_NB_CORE,
		SMALL_PAGE_SIZE)]
	__aligned(SMALL_PAGE_SIZE)
#ifndef CFG_NS_VIRTUALIZATION
	__section(".nozi.kdata_page");
#else
	__section(".nex_nozi.kdata_page");
#endif
#endif

#ifdef ARM32
uint32_t __nostackcheck thread_get_exceptions(void)
{
	uint32_t cpsr = read_cpsr();

	return (cpsr >> CPSR_F_SHIFT) & THREAD_EXCP_ALL;
}

void __nostackcheck thread_set_exceptions(uint32_t exceptions)
{
	uint32_t cpsr = read_cpsr();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	cpsr &= ~(THREAD_EXCP_ALL << CPSR_F_SHIFT);
	cpsr |= ((exceptions & THREAD_EXCP_ALL) << CPSR_F_SHIFT);

	barrier();
	write_cpsr(cpsr);
	barrier();
}
#endif /*ARM32*/

#ifdef ARM64
uint32_t __nostackcheck thread_get_exceptions(void)
{
	uint32_t daif = read_daif();

	return (daif >> DAIF_F_SHIFT) & THREAD_EXCP_ALL;
}

void __nostackcheck thread_set_exceptions(uint32_t exceptions)
{
	uint32_t daif = read_daif();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	daif &= ~(THREAD_EXCP_ALL << DAIF_F_SHIFT);
	daif |= ((exceptions & THREAD_EXCP_ALL) << DAIF_F_SHIFT);

	barrier();
	write_daif(daif);
	barrier();
}
#endif /*ARM64*/

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
#ifdef CFG_WITH_VFP
	struct thread_ctx *thr = threads + thread_get_id();

	thr->vfp_state.ns_saved = false;
	vfp_lazy_save_state_init(&thr->vfp_state.ns);
#endif /*CFG_WITH_VFP*/
}

static void thread_lazy_restore_ns_vfp(void)
{
#ifdef CFG_WITH_VFP
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(!thr->vfp_state.sec_lazy_saved && !thr->vfp_state.sec_saved);

	if (tuv && tuv->lazy_saved && !tuv->saved) {
		vfp_lazy_save_state_final(&tuv->vfp, false /*!force_save*/);
		tuv->saved = true;
	}

	vfp_lazy_restore_state(&thr->vfp_state.ns, thr->vfp_state.ns_saved);
	thr->vfp_state.ns_saved = false;
#endif /*CFG_WITH_VFP*/
}

#ifdef ARM32
static void init_regs(struct thread_ctx *thread, uint32_t a0, uint32_t a1,
		      uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
		      uint32_t a6, uint32_t a7, void *pc)
{
	thread->regs.pc = (uint32_t)pc;

	/*
	 * Stdcalls starts in SVC mode with masked foreign interrupts, masked
	 * Asynchronous abort and unmasked native interrupts.
	 */
	thread->regs.cpsr = read_cpsr() & ARM32_CPSR_E;
	thread->regs.cpsr |= CPSR_MODE_SVC | CPSR_A |
			(THREAD_EXCP_FOREIGN_INTR << ARM32_CPSR_F_SHIFT);
	/* Enable thumb mode if it's a thumb instruction */
	if (thread->regs.pc & 1)
		thread->regs.cpsr |= CPSR_T;
	/* Reinitialize stack pointer */
	thread->regs.svc_sp = thread->stack_va_end;

	/*
	 * Copy arguments into context. This will make the
	 * arguments appear in r0-r7 when thread is started.
	 */
	thread->regs.r0 = a0;
	thread->regs.r1 = a1;
	thread->regs.r2 = a2;
	thread->regs.r3 = a3;
	thread->regs.r4 = a4;
	thread->regs.r5 = a5;
	thread->regs.r6 = a6;
	thread->regs.r7 = a7;
}
#endif /*ARM32*/

#ifdef ARM64
static void init_regs(struct thread_ctx *thread, uint32_t a0, uint32_t a1,
		      uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5,
		      uint32_t a6, uint32_t a7, void *pc)
{
	thread->regs.pc = (uint64_t)pc;

	/*
	 * Stdcalls starts in SVC mode with masked foreign interrupts, masked
	 * Asynchronous abort and unmasked native interrupts.
	 */
	thread->regs.cpsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0,
				THREAD_EXCP_FOREIGN_INTR | DAIFBIT_ABT);
	/* Reinitialize stack pointer */
	thread->regs.sp = thread->stack_va_end;

	/*
	 * Copy arguments into context. This will make the
	 * arguments appear in x0-x7 when thread is started.
	 */
	thread->regs.x[0] = a0;
	thread->regs.x[1] = a1;
	thread->regs.x[2] = a2;
	thread->regs.x[3] = a3;
	thread->regs.x[4] = a4;
	thread->regs.x[5] = a5;
	thread->regs.x[6] = a6;
	thread->regs.x[7] = a7;

	/* Set up frame pointer as per the Aarch64 AAPCS */
	thread->regs.x[29] = 0;
}
#endif /*ARM64*/

static void __thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2,
				   uint32_t a3, uint32_t a4, uint32_t a5,
				   uint32_t a6, uint32_t a7,
				   void *pc, uint32_t flags)
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

	threads[n].flags = flags;
	init_regs(threads + n, a0, a1, a2, a3, a4, a5, a6, a7, pc);
#ifdef CFG_CORE_PAUTH
	/*
	 * Copy the APIA key into the registers to be restored with
	 * thread_resume().
	 */
	threads[n].regs.apiakey_hi = threads[n].keys.apia_hi;
	threads[n].regs.apiakey_lo = threads[n].keys.apia_lo;
#endif

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
			       thread_std_smc_entry, 0);
}

#ifdef CFG_SECURE_PARTITION
void thread_sp_alloc_and_run(struct thread_smc_args *args __maybe_unused)
{
	__thread_alloc_and_run(args->a0, args->a1, args->a2, args->a3, args->a4,
			       args->a5, args->a6, args->a7,
			       spmc_sp_thread_entry, THREAD_FLAGS_FFA_ONLY);
}
#endif

#ifdef ARM32
static void copy_a0_to_a3(struct thread_ctx_regs *regs, uint32_t a0,
			  uint32_t a1, uint32_t a2, uint32_t a3)
{
	/*
	 * Update returned values from RPC, values will appear in
	 * r0-r3 when thread is resumed.
	 */
	regs->r0 = a0;
	regs->r1 = a1;
	regs->r2 = a2;
	regs->r3 = a3;
}
#endif /*ARM32*/

#ifdef ARM64
static void copy_a0_to_a3(struct thread_ctx_regs *regs, uint32_t a0,
			  uint32_t a1, uint32_t a2, uint32_t a3)
{
	/*
	 * Update returned values from RPC, values will appear in
	 * x0-x3 when thread is resumed.
	 */
	regs->x[0] = a0;
	regs->x[1] = a1;
	regs->x[2] = a2;
	regs->x[3] = a3;
}
#endif /*ARM64*/

#ifdef ARM32
static bool is_from_user(uint32_t cpsr)
{
	return (cpsr & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_USR;
}
#endif

#ifdef ARM64
static bool is_from_user(uint32_t cpsr)
{
	if (cpsr & (SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT))
		return true;
	if (((cpsr >> SPSR_64_MODE_EL_SHIFT) & SPSR_64_MODE_EL_MASK) ==
	     SPSR_64_MODE_EL0)
		return true;
	return false;
}
#endif

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

static bool is_user_mode(struct thread_ctx_regs *regs)
{
	return is_from_user((uint32_t)regs->cpsr);
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

#ifdef ARM64
static uint64_t spsr_from_pstate(void)
{
	uint64_t spsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0, 0);

	spsr |= read_daif();
	if (IS_ENABLED(CFG_PAN) && feat_pan_implemented() && read_pan())
		spsr |= SPSR_64_PAN;

	return spsr;
}

void __thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS])
{
	thread_rpc_spsr(rv, spsr_from_pstate());
}

vaddr_t thread_get_saved_thread_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);
	return threads[ct].kern_sp;
}
#endif /*ARM64*/

#ifdef ARM32
bool thread_is_in_normal_mode(void)
{
	return (read_cpsr() & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_SVC;
}
#endif

void thread_state_free(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	thread_lazy_restore_ns_vfp();
	tee_pager_release_phys(
		(void *)(threads[ct].stack_va_end - STACK_THREAD_SIZE),
		STACK_THREAD_SIZE);

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = THREAD_ID_INVALID;

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
		virt_unset_guest();
	thread_unlock_global();
}

#ifdef CFG_WITH_PAGER
static void release_unused_kernel_stack(struct thread_ctx *thr,
					uint32_t cpsr __maybe_unused)
{
#ifdef ARM64
	/*
	 * If we're from user mode then thr->regs.sp is the saved user
	 * stack pointer and thr->kern_sp holds the last kernel stack
	 * pointer. But if we're from kernel mode then thr->kern_sp isn't
	 * up to date so we need to read from thr->regs.sp instead.
	 */
	vaddr_t sp = is_from_user(cpsr) ?  thr->kern_sp : thr->regs.sp;
#else
	vaddr_t sp = thr->regs.svc_sp;
#endif
	vaddr_t base = thr->stack_va_end - STACK_THREAD_SIZE;
	size_t len = sp - base;

	tee_pager_release_phys((void *)base, len);
}
#else
static void release_unused_kernel_stack(struct thread_ctx *thr __unused,
					uint32_t cpsr __unused)
{
}
#endif

int thread_state_suspend(uint32_t flags, uint32_t cpsr, vaddr_t pc)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != THREAD_ID_INVALID);

	if (core_mmu_user_mapping_is_active())
		ftrace_suspend();

	thread_check_canaries();

	release_unused_kernel_stack(threads + ct, cpsr);

	if (is_from_user(cpsr)) {
		thread_user_save_vfp();
		tee_ta_update_session_utime_suspend();
		tee_ta_gprof_sample_pc(pc);
	}
	thread_lazy_restore_ns_vfp();

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].flags |= flags;
	threads[ct].regs.cpsr = cpsr;
	threads[ct].regs.pc = pc;
	threads[ct].state = THREAD_STATE_SUSPENDED;

	threads[ct].have_user_map = core_mmu_user_mapping_is_active();
	if (threads[ct].have_user_map) {
		if (threads[ct].flags & THREAD_FLAGS_EXIT_ON_FOREIGN_INTR)
			tee_ta_ftrace_update_times_suspend();
		core_mmu_get_user_map(&threads[ct].user_map);
		core_mmu_set_user_map(NULL);
	}

	if (IS_ENABLED(CFG_SECURE_PARTITION)) {
		struct ts_session *ts_sess =
			TAILQ_FIRST(&threads[ct].tsd.sess_stack);

		spmc_sp_set_to_preempted(ts_sess);
	}

	l->curr_thread = THREAD_ID_INVALID;

	if (IS_ENABLED(CFG_NS_VIRTUALIZATION))
		virt_unset_guest();

	thread_unlock_global();

	return ct;
}

bool thread_init_stack(uint32_t thread_id, vaddr_t sp)
{
	if (thread_id >= CFG_NUM_THREADS)
		return false;
	threads[thread_id].stack_va_end = sp;
	return true;
}

static void __maybe_unused
set_core_local_kcode_offset(struct thread_core_local *cls, long offset)
{
	size_t n = 0;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		cls[n].kcode_offset = offset;
}

static void init_user_kcode(void)
{
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	vaddr_t v = (vaddr_t)thread_excp_vect;
	vaddr_t ve = (vaddr_t)thread_excp_vect_end;

	thread_user_kcode_va = ROUNDDOWN(v, CORE_MMU_USER_CODE_SIZE);
	ve = ROUNDUP(ve, CORE_MMU_USER_CODE_SIZE);
	thread_user_kcode_size = ve - thread_user_kcode_va;

	core_mmu_get_user_va_range(&v, NULL);
	thread_user_kcode_offset = thread_user_kcode_va - v;

	set_core_local_kcode_offset(thread_core_local,
				    thread_user_kcode_offset);
#if defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC) && defined(ARM64)
	set_core_local_kcode_offset((void *)thread_user_kdata_page,
				    thread_user_kcode_offset);
	/*
	 * When transitioning to EL0 subtract SP with this much to point to
	 * this special kdata page instead. SP is restored by add this much
	 * while transitioning back to EL1.
	 */
	v += thread_user_kcode_size;
	thread_user_kdata_sp_offset = (vaddr_t)thread_core_local - v;
#endif
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/
}

void thread_init_primary(void)
{
	/* Initialize canaries around the stacks */
	thread_init_canaries();

	init_user_kcode();
}

static uint32_t __maybe_unused get_midr_implementer(uint32_t midr)
{
	return (midr >> MIDR_IMPLEMENTER_SHIFT) & MIDR_IMPLEMENTER_MASK;
}

static uint32_t __maybe_unused get_midr_primary_part(uint32_t midr)
{
	return (midr >> MIDR_PRIMARY_PART_NUM_SHIFT) &
	       MIDR_PRIMARY_PART_NUM_MASK;
}

static uint32_t __maybe_unused get_midr_variant(uint32_t midr)
{
	return (midr >> MIDR_VARIANT_SHIFT) & MIDR_VARIANT_MASK;
}

static uint32_t __maybe_unused get_midr_revision(uint32_t midr)
{
	return (midr >> MIDR_REVISION_SHIFT) & MIDR_REVISION_MASK;
}

#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
#ifdef ARM64
static bool probe_workaround_available(uint32_t wa_id)
{
	int32_t r;

	r = thread_smc(SMCCC_VERSION, 0, 0, 0);
	if (r < 0)
		return false;
	if (r < 0x10001)	/* compare with version 1.1 */
		return false;

	/* Version >= 1.1, so SMCCC_ARCH_FEATURES is available */
	r = thread_smc(SMCCC_ARCH_FEATURES, wa_id, 0, 0);
	return r >= 0;
}

static vaddr_t __maybe_unused select_vector_wa_spectre_v2(void)
{
	if (probe_workaround_available(SMCCC_ARCH_WORKAROUND_1)) {
		DMSG("SMCCC_ARCH_WORKAROUND_1 (%#08" PRIx32 ") available",
		     SMCCC_ARCH_WORKAROUND_1);
		DMSG("SMC Workaround for CVE-2017-5715 used");
		return (vaddr_t)thread_excp_vect_wa_spectre_v2;
	}

	DMSG("SMCCC_ARCH_WORKAROUND_1 (%#08" PRIx32 ") unavailable",
	     SMCCC_ARCH_WORKAROUND_1);
	DMSG("SMC Workaround for CVE-2017-5715 not needed (if ARM-TF is up to date)");
	return (vaddr_t)thread_excp_vect;
}
#else
static vaddr_t __maybe_unused select_vector_wa_spectre_v2(void)
{
	return (vaddr_t)thread_excp_vect_wa_spectre_v2;
}
#endif
#endif

#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
static vaddr_t select_vector_wa_spectre_bhb(uint8_t loop_count __maybe_unused)
{
	/*
	 * Spectre-BHB has only been analyzed for AArch64 so far. For
	 * AArch32 fall back to the Spectre-V2 workaround which is likely
	 * to work even if perhaps a bit more expensive than a more
	 * optimized workaround.
	 */
#ifdef ARM64
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	struct thread_core_local *cl = (void *)thread_user_kdata_page;

	cl[get_core_pos()].bhb_loop_count = loop_count;
#endif
	thread_get_core_local()->bhb_loop_count = loop_count;

	DMSG("Spectre-BHB CVE-2022-23960 workaround enabled with \"K\" = %u",
	     loop_count);

	return (vaddr_t)thread_excp_vect_wa_spectre_bhb;
#else
	return select_vector_wa_spectre_v2();
#endif
}
#endif

static vaddr_t get_excp_vect(void)
{
#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
	uint32_t midr = read_midr();
	uint8_t vers = 0;

	if (get_midr_implementer(midr) != MIDR_IMPLEMENTER_ARM)
		return (vaddr_t)thread_excp_vect;
	/*
	 * Variant rx, Revision py, for instance
	 * Variant 2 Revision 0 = r2p0 = 0x20
	 */
	vers = (get_midr_variant(midr) << 4) | get_midr_revision(midr);

	/*
	 * Spectre-V2 (CVE-2017-5715) software workarounds covers what's
	 * needed for Spectre-BHB (CVE-2022-23960) too. The workaround for
	 * Spectre-V2 is more expensive than the one for Spectre-BHB so if
	 * possible select the workaround for Spectre-BHB.
	 */
	switch (get_midr_primary_part(midr)) {
#ifdef ARM32
	/* Spectre-V2 */
	case CORTEX_A8_PART_NUM:
	case CORTEX_A9_PART_NUM:
	case CORTEX_A17_PART_NUM:
#endif
	/* Spectre-V2 */
	case CORTEX_A57_PART_NUM:
	case CORTEX_A73_PART_NUM:
	case CORTEX_A75_PART_NUM:
		return select_vector_wa_spectre_v2();
#ifdef ARM32
	/* Spectre-V2 */
	case CORTEX_A15_PART_NUM:
		return (vaddr_t)thread_excp_vect_wa_a15_spectre_v2;
#endif
	/*
	 * Spectre-V2 for vers < r1p0
	 * Spectre-BHB for vers >= r1p0
	 */
	case CORTEX_A72_PART_NUM:
		if (vers < 0x10)
			return select_vector_wa_spectre_v2();
		return select_vector_wa_spectre_bhb(8);

	/*
	 * Doing the more safe but expensive Spectre-V2 workaround for CPUs
	 * still being researched on the best mitigation sequence.
	 */
	case CORTEX_A65_PART_NUM:
	case CORTEX_A65AE_PART_NUM:
	case NEOVERSE_E1_PART_NUM:
		return select_vector_wa_spectre_v2();

	/* Spectre-BHB */
	case CORTEX_A76_PART_NUM:
	case CORTEX_A76AE_PART_NUM:
	case CORTEX_A77_PART_NUM:
		return select_vector_wa_spectre_bhb(24);
	case CORTEX_A78_PART_NUM:
	case CORTEX_A78AE_PART_NUM:
	case CORTEX_A78C_PART_NUM:
	case CORTEX_A710_PART_NUM:
	case CORTEX_X1_PART_NUM:
	case CORTEX_X2_PART_NUM:
		return select_vector_wa_spectre_bhb(32);
	case NEOVERSE_N1_PART_NUM:
		return select_vector_wa_spectre_bhb(24);
	case NEOVERSE_N2_PART_NUM:
	case NEOVERSE_V1_PART_NUM:
		return select_vector_wa_spectre_bhb(32);

	default:
		return (vaddr_t)thread_excp_vect;
	}
#endif /*CFG_CORE_WORKAROUND_SPECTRE_BP_SEC*/

	return (vaddr_t)thread_excp_vect;
}

void thread_init_per_cpu(void)
{
#ifdef ARM32
	struct thread_core_local *l = thread_get_core_local();

#if !defined(CFG_WITH_ARM_TRUSTED_FW)
	/* Initialize secure monitor */
	sm_init(l->tmp_stack_va_end + STACK_TMP_OFFS);
#endif
	thread_set_irq_sp(l->tmp_stack_va_end);
	thread_set_fiq_sp(l->tmp_stack_va_end);
	thread_set_abt_sp((vaddr_t)l);
	thread_set_und_sp((vaddr_t)l);
#endif

	thread_init_vbar(get_excp_vect());

#ifdef CFG_FTRACE_SUPPORT
	/*
	 * Enable accesses to frequency register and physical counter
	 * register in EL0/PL0 required for timestamping during
	 * function tracing.
	 */
	write_cntkctl(read_cntkctl() | CNTKCTL_PL0PCTEN);
#endif
}

#ifdef CFG_WITH_VFP
uint32_t thread_kernel_enable_vfp(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(!vfp_is_enabled());

	if (!thr->vfp_state.ns_saved) {
		vfp_lazy_save_state_final(&thr->vfp_state.ns,
					  true /*force_save*/);
		thr->vfp_state.ns_saved = true;
	} else if (thr->vfp_state.sec_lazy_saved &&
		   !thr->vfp_state.sec_saved) {
		/*
		 * This happens when we're handling an abort while the
		 * thread was using the VFP state.
		 */
		vfp_lazy_save_state_final(&thr->vfp_state.sec,
					  false /*!force_save*/);
		thr->vfp_state.sec_saved = true;
	} else if (tuv && tuv->lazy_saved && !tuv->saved) {
		/*
		 * This can happen either during syscall or abort
		 * processing (while processing a syscall).
		 */
		vfp_lazy_save_state_final(&tuv->vfp, false /*!force_save*/);
		tuv->saved = true;
	}

	vfp_enable();
	return exceptions;
}

void thread_kernel_disable_vfp(uint32_t state)
{
	uint32_t exceptions;

	assert(vfp_is_enabled());

	vfp_disable();
	exceptions = thread_get_exceptions();
	assert(exceptions & THREAD_EXCP_FOREIGN_INTR);
	exceptions &= ~THREAD_EXCP_FOREIGN_INTR;
	exceptions |= state & THREAD_EXCP_FOREIGN_INTR;
	thread_set_exceptions(exceptions);
}

void thread_kernel_save_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	if (vfp_is_enabled()) {
		vfp_lazy_save_state_init(&thr->vfp_state.sec);
		thr->vfp_state.sec_lazy_saved = true;
	}
}

void thread_kernel_restore_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	assert(!vfp_is_enabled());
	if (thr->vfp_state.sec_lazy_saved) {
		vfp_lazy_restore_state(&thr->vfp_state.sec,
				       thr->vfp_state.sec_saved);
		thr->vfp_state.sec_saved = false;
		thr->vfp_state.sec_lazy_saved = false;
	}
}

void thread_user_enable_vfp(struct thread_user_vfp_state *uvfp)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	assert(!vfp_is_enabled());

	if (!thr->vfp_state.ns_saved) {
		vfp_lazy_save_state_final(&thr->vfp_state.ns,
					  true /*force_save*/);
		thr->vfp_state.ns_saved = true;
	} else if (tuv && uvfp != tuv) {
		if (tuv->lazy_saved && !tuv->saved) {
			vfp_lazy_save_state_final(&tuv->vfp,
						  false /*!force_save*/);
			tuv->saved = true;
		}
	}

	if (uvfp->lazy_saved)
		vfp_lazy_restore_state(&uvfp->vfp, uvfp->saved);
	uvfp->lazy_saved = false;
	uvfp->saved = false;

	thr->vfp_state.uvfp = uvfp;
	vfp_enable();
}

void thread_user_save_vfp(void)
{
	struct thread_ctx *thr = threads + thread_get_id();
	struct thread_user_vfp_state *tuv = thr->vfp_state.uvfp;

	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);
	if (!vfp_is_enabled())
		return;

	assert(tuv && !tuv->lazy_saved && !tuv->saved);
	vfp_lazy_save_state_init(&tuv->vfp);
	tuv->lazy_saved = true;
}

void thread_user_clear_vfp(struct user_mode_ctx *uctx)
{
	struct thread_user_vfp_state *uvfp = &uctx->vfp;
	struct thread_ctx *thr = threads + thread_get_id();

	if (uvfp == thr->vfp_state.uvfp)
		thr->vfp_state.uvfp = NULL;
	uvfp->lazy_saved = false;
	uvfp->saved = false;
}
#endif /*CFG_WITH_VFP*/

#ifdef ARM32
static bool get_spsr(bool is_32bit, unsigned long entry_func, uint32_t *spsr)
{
	uint32_t s;

	if (!is_32bit)
		return false;

	s = read_cpsr();
	s &= ~(CPSR_MODE_MASK | CPSR_T | CPSR_IT_MASK1 | CPSR_IT_MASK2);
	s |= CPSR_MODE_USR;
	if (entry_func & 1)
		s |= CPSR_T;
	*spsr = s;
	return true;
}
#endif

#ifdef ARM64
static bool get_spsr(bool is_32bit, unsigned long entry_func, uint32_t *spsr)
{
	uint32_t s;

	if (is_32bit) {
		s = read_daif() & (SPSR_32_AIF_MASK << SPSR_32_AIF_SHIFT);
		s |= SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT;
		s |= (entry_func & SPSR_32_T_MASK) << SPSR_32_T_SHIFT;
	} else {
		s = read_daif() & (SPSR_64_DAIF_MASK << SPSR_64_DAIF_SHIFT);
	}

	*spsr = s;
	return true;
}
#endif

static void set_ctx_regs(struct thread_ctx_regs *regs, unsigned long a0,
			 unsigned long a1, unsigned long a2, unsigned long a3,
			 unsigned long user_sp, unsigned long entry_func,
			 uint32_t spsr,
			 struct thread_pauth_keys *keys __maybe_unused)
{
	/*
	 * First clear all registers to avoid leaking information from
	 * other TAs or even the Core itself.
	 */
	*regs = (struct thread_ctx_regs){ };
#ifdef ARM32
	regs->r0 = a0;
	regs->r1 = a1;
	regs->r2 = a2;
	regs->r3 = a3;
	regs->usr_sp = user_sp;
	regs->pc = entry_func;
	regs->cpsr = spsr;
#endif
#ifdef ARM64
	regs->x[0] = a0;
	regs->x[1] = a1;
	regs->x[2] = a2;
	regs->x[3] = a3;
	regs->sp = user_sp;
	regs->pc = entry_func;
	regs->cpsr = spsr;
	regs->x[13] = user_sp;	/* Used when running TA in Aarch32 */
	regs->sp = user_sp;	/* Used when running TA in Aarch64 */
#ifdef CFG_TA_PAUTH
	assert(keys);
	regs->apiakey_hi = keys->apia_hi;
	regs->apiakey_lo = keys->apia_lo;
#endif
	/* Set frame pointer (user stack can't be unwound past this point) */
	regs->x[29] = 0;
#endif
}

static struct thread_pauth_keys *thread_get_pauth_keys(void)
{
#if defined(CFG_TA_PAUTH)
	struct ts_session *s = ts_get_current_session();
	/* Only user TA's support the PAUTH keys */
	struct user_ta_ctx *utc = to_user_ta_ctx(s->ctx);

	return &utc->uctx.keys;
#else
	return NULL;
#endif
}

uint32_t thread_enter_user_mode(unsigned long a0, unsigned long a1,
		unsigned long a2, unsigned long a3, unsigned long user_sp,
		unsigned long entry_func, bool is_32bit,
		uint32_t *exit_status0, uint32_t *exit_status1)
{
	uint32_t spsr = 0;
	uint32_t exceptions = 0;
	uint32_t rc = 0;
	struct thread_ctx_regs *regs = NULL;
	struct thread_pauth_keys *keys = NULL;

	tee_ta_update_session_utime_resume();

	keys = thread_get_pauth_keys();

	/* Derive SPSR from current CPSR/PSTATE readout. */
	if (!get_spsr(is_32bit, entry_func, &spsr)) {
		*exit_status0 = 1; /* panic */
		*exit_status1 = 0xbadbadba;
		return 0;
	}

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	/*
	 * We're using the per thread location of saved context registers
	 * for temporary storage. Now that exceptions are masked they will
	 * not be used for any thing else until they are eventually
	 * unmasked when user mode has been entered.
	 */
	regs = thread_get_ctx_regs();
	set_ctx_regs(regs, a0, a1, a2, a3, user_sp, entry_func, spsr, keys);
	rc = __thread_enter_user_mode(regs, exit_status0, exit_status1);
	thread_unmask_exceptions(exceptions);
	return rc;
}

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
			   vaddr_t *va, size_t *sz)
{
	core_mmu_get_user_va_range(va, NULL);
	*mobj = mobj_tee_ram_rx;
	*sz = thread_user_kcode_size;
	*offset = thread_user_kcode_va - (vaddr_t)mobj_get_va(*mobj, 0, *sz);
}
#endif

#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) && \
	defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC) && defined(ARM64)
void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
			   vaddr_t *va, size_t *sz)
{
	vaddr_t v;

	core_mmu_get_user_va_range(&v, NULL);
	*va = v + thread_user_kcode_size;
	*mobj = mobj_tee_ram_rw;
	*sz = sizeof(thread_user_kdata_page);
	*offset = (vaddr_t)thread_user_kdata_page -
		  (vaddr_t)mobj_get_va(*mobj, 0, *sz);
}
#endif

static void setup_unwind_user_mode(struct thread_scall_regs *regs)
{
#ifdef ARM32
	regs->lr = (uintptr_t)thread_unwind_user_mode;
	regs->spsr = read_cpsr();
#endif
#ifdef ARM64
	regs->elr = (uintptr_t)thread_unwind_user_mode;
	regs->spsr = spsr_from_pstate();
	/*
	 * Regs is the value of stack pointer before calling the SVC
	 * handler.  By the addition matches for the reserved space at the
	 * beginning of el0_sync_svc(). This prepares the stack when
	 * returning to thread_unwind_user_mode instead of a normal
	 * exception return.
	 */
	regs->sp_el0 = (uint64_t)(regs + 1);
#endif
}

static void gprof_set_status(struct ts_session *s __maybe_unused,
			     enum ts_gprof_status status __maybe_unused)
{
#ifdef CFG_TA_GPROF_SUPPORT
	if (s->ctx->ops->gprof_set_status)
		s->ctx->ops->gprof_set_status(status);
#endif
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak thread_scall_handler(struct thread_scall_regs *regs)
{
	struct ts_session *sess = NULL;
	uint32_t state = 0;

	/* Enable native interrupts */
	state = thread_get_exceptions();
	thread_unmask_exceptions(state & ~THREAD_EXCP_NATIVE_INTR);

	thread_user_save_vfp();

	sess = ts_get_current_session();
	/*
	 * User mode service has just entered kernel mode, suspend gprof
	 * collection until we're about to switch back again.
	 */
	gprof_set_status(sess, TS_GPROF_SUSPEND);

	/* Restore foreign interrupts which are disabled on exception entry */
	thread_restore_foreign_intr();

	assert(sess && sess->handle_scall);
	if (sess->handle_scall(regs)) {
		/* We're about to switch back to user mode */
		gprof_set_status(sess, TS_GPROF_RESUME);
	} else {
		/* We're returning from __thread_enter_user_mode() */
		setup_unwind_user_mode(regs);
	}
}

#ifdef CFG_WITH_ARM_TRUSTED_FW
/*
 * These five functions are __weak to allow platforms to override them if
 * needed.
 */
unsigned long __weak thread_cpu_off_handler(unsigned long a0 __unused,
					    unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_cpu_off_handler);

unsigned long __weak thread_cpu_suspend_handler(unsigned long a0 __unused,
						unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_cpu_suspend_handler);

unsigned long __weak thread_cpu_resume_handler(unsigned long a0 __unused,
					       unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_cpu_resume_handler);

unsigned long __weak thread_system_off_handler(unsigned long a0 __unused,
					       unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_system_off_handler);

unsigned long __weak thread_system_reset_handler(unsigned long a0 __unused,
						 unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(thread_system_reset_handler);
#endif /*CFG_WITH_ARM_TRUSTED_FW*/

#ifdef CFG_CORE_WORKAROUND_ARM_NMFI
void __noreturn interrupt_main_handler(void)
{
	/*
	 * Note: overrides the default implementation of this function so that
	 * if there would be another handler defined there would be duplicate
	 * symbol error during linking.
	 */
	panic("Secure interrupt received but it is not supported");
}
#endif
