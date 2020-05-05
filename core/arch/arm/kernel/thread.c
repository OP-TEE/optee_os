// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <platform_config.h>

#include <arm.h>
#include <assert.h>
#include <io.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/linker.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread_defs.h>
#include <kernel/thread.h>
#include <kernel/virtualization.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <smccc.h>
#include <sm/sm.h>
#include <trace.h>
#include <util.h>

#include "thread_private.h"

#ifdef CFG_WITH_ARM_TRUSTED_FW
#define STACK_TMP_OFFS		0
#else
#define STACK_TMP_OFFS		SM_STACK_TMP_RESERVE_SIZE
#endif


#ifdef ARM32
#ifdef CFG_CORE_SANITIZE_KADDRESS
#define STACK_TMP_SIZE		(3072 + STACK_TMP_OFFS)
#else
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS)
#endif
#define STACK_THREAD_SIZE	8192

#if defined(CFG_CORE_SANITIZE_KADDRESS) || defined(__clang__)
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		2048
#endif

#endif /*ARM32*/

#ifdef ARM64
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS)
#define STACK_THREAD_SIZE	8192

#if TRACE_LEVEL > 0
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		1024
#endif
#endif /*ARM64*/

struct thread_ctx threads[CFG_NUM_THREADS];

struct thread_core_local thread_core_local[CFG_TEE_CORE_NB_CORE] __nex_bss;

#ifdef CFG_WITH_STACK_CANARIES
#ifdef ARM32
#define STACK_CANARY_SIZE	(4 * sizeof(uint32_t))
#endif
#ifdef ARM64
#define STACK_CANARY_SIZE	(8 * sizeof(uint32_t))
#endif
#define START_CANARY_VALUE	0xdededede
#define END_CANARY_VALUE	0xabababab
#define GET_START_CANARY(name, stack_num) name[stack_num][0]
#define GET_END_CANARY(name, stack_num) \
	name[stack_num][sizeof(name[stack_num]) / sizeof(uint32_t) - 1]
#else
#define STACK_CANARY_SIZE	0
#endif

#define DECLARE_STACK(name, num_stacks, stack_size, linkage) \
linkage uint32_t name[num_stacks] \
		[ROUNDUP(stack_size + STACK_CANARY_SIZE, STACK_ALIGNMENT) / \
		sizeof(uint32_t)] \
		__attribute__((section(".nozi_stack." # name), \
			       aligned(STACK_ALIGNMENT)))

#define STACK_SIZE(stack) (sizeof(stack) - STACK_CANARY_SIZE / 2)

#define GET_STACK(stack) \
	((vaddr_t)(stack) + STACK_SIZE(stack))

DECLARE_STACK(stack_tmp, CFG_TEE_CORE_NB_CORE, STACK_TMP_SIZE, static);
DECLARE_STACK(stack_abt, CFG_TEE_CORE_NB_CORE, STACK_ABT_SIZE, static);
#ifndef CFG_WITH_PAGER
DECLARE_STACK(stack_thread, CFG_NUM_THREADS, STACK_THREAD_SIZE, static);
#endif

const void *stack_tmp_export __section(".identity_map.stack_tmp_export") =
	(uint8_t *)stack_tmp + sizeof(stack_tmp[0]) -
	(STACK_TMP_OFFS + STACK_CANARY_SIZE / 2);
const uint32_t stack_tmp_stride __section(".identity_map.stack_tmp_stride") =
	sizeof(stack_tmp[0]);

/*
 * These stack setup info are required by secondary boot cores before they
 * each locally enable the pager (the mmu). Hence kept in pager sections.
 */
DECLARE_KEEP_PAGER(stack_tmp_export);
DECLARE_KEEP_PAGER(stack_tmp_stride);

thread_pm_handler_t thread_cpu_on_handler_ptr __nex_bss;
thread_pm_handler_t thread_cpu_off_handler_ptr __nex_bss;
thread_pm_handler_t thread_cpu_suspend_handler_ptr __nex_bss;
thread_pm_handler_t thread_cpu_resume_handler_ptr __nex_bss;
thread_pm_handler_t thread_system_off_handler_ptr __nex_bss;
thread_pm_handler_t thread_system_reset_handler_ptr __nex_bss;

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
static vaddr_t thread_user_kcode_va __nex_bss;
long thread_user_kcode_offset __nex_bss;
static size_t thread_user_kcode_size __nex_bss;
#endif

#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) && \
	defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC) && defined(ARM64)
long thread_user_kdata_sp_offset __nex_bss;
static uint8_t thread_user_kdata_page[
	ROUNDUP(sizeof(thread_core_local), SMALL_PAGE_SIZE)]
	__aligned(SMALL_PAGE_SIZE)
#ifndef CFG_VIRTUALIZATION
	__section(".nozi.kdata_page");
#else
	__section(".nex_nozi.kdata_page");
#endif
#endif

static unsigned int thread_global_lock __nex_bss = SPINLOCK_UNLOCK;

static void init_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	size_t n;
#define INIT_CANARY(name)						\
	for (n = 0; n < ARRAY_SIZE(name); n++) {			\
		uint32_t *start_canary = &GET_START_CANARY(name, n);	\
		uint32_t *end_canary = &GET_END_CANARY(name, n);	\
									\
		*start_canary = START_CANARY_VALUE;			\
		*end_canary = END_CANARY_VALUE;				\
		DMSG("#Stack canaries for %s[%zu] with top at %p",	\
			#name, n, (void *)(end_canary - 1));		\
		DMSG("watch *%p", (void *)end_canary);			\
	}

	INIT_CANARY(stack_tmp);
	INIT_CANARY(stack_abt);
#if !defined(CFG_WITH_PAGER) && !defined(CFG_VIRTUALIZATION)
	INIT_CANARY(stack_thread);
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

#define CANARY_DIED(stack, loc, n) \
	do { \
		EMSG_RAW("Dead canary at %s of '%s[%zu]'", #loc, #stack, n); \
		panic(); \
	} while (0)

void thread_check_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	size_t n;

	for (n = 0; n < ARRAY_SIZE(stack_tmp); n++) {
		if (GET_START_CANARY(stack_tmp, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_tmp, start, n);
		if (GET_END_CANARY(stack_tmp, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_tmp, end, n);
	}

	for (n = 0; n < ARRAY_SIZE(stack_abt); n++) {
		if (GET_START_CANARY(stack_abt, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_abt, start, n);
		if (GET_END_CANARY(stack_abt, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_abt, end, n);

	}
#if !defined(CFG_WITH_PAGER) && !defined(CFG_VIRTUALIZATION)
	for (n = 0; n < ARRAY_SIZE(stack_thread); n++) {
		if (GET_START_CANARY(stack_thread, n) != START_CANARY_VALUE)
			CANARY_DIED(stack_thread, start, n);
		if (GET_END_CANARY(stack_thread, n) != END_CANARY_VALUE)
			CANARY_DIED(stack_thread, end, n);
	}
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
}

void thread_lock_global(void)
{
	cpu_spin_lock(&thread_global_lock);
}

void thread_unlock_global(void)
{
	cpu_spin_unlock(&thread_global_lock);
}

#ifdef ARM32
uint32_t thread_get_exceptions(void)
{
	uint32_t cpsr = read_cpsr();

	return (cpsr >> CPSR_F_SHIFT) & THREAD_EXCP_ALL;
}

void thread_set_exceptions(uint32_t exceptions)
{
	uint32_t cpsr = read_cpsr();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	cpsr &= ~(THREAD_EXCP_ALL << CPSR_F_SHIFT);
	cpsr |= ((exceptions & THREAD_EXCP_ALL) << CPSR_F_SHIFT);
	write_cpsr(cpsr);
}
#endif /*ARM32*/

#ifdef ARM64
uint32_t thread_get_exceptions(void)
{
	uint32_t daif = read_daif();

	return (daif >> DAIF_F_SHIFT) & THREAD_EXCP_ALL;
}

void thread_set_exceptions(uint32_t exceptions)
{
	uint32_t daif = read_daif();

	/* Foreign interrupts must not be unmasked while holding a spinlock */
	if (!(exceptions & THREAD_EXCP_FOREIGN_INTR))
		assert_have_no_spinlock();

	daif &= ~(THREAD_EXCP_ALL << DAIF_F_SHIFT);
	daif |= ((exceptions & THREAD_EXCP_ALL) << DAIF_F_SHIFT);
	write_daif(daif);
}
#endif /*ARM64*/

uint32_t thread_mask_exceptions(uint32_t exceptions)
{
	uint32_t state = thread_get_exceptions();

	thread_set_exceptions(state | (exceptions & THREAD_EXCP_ALL));
	return state;
}

void thread_unmask_exceptions(uint32_t state)
{
	thread_set_exceptions(state & THREAD_EXCP_ALL);
}


struct thread_core_local *thread_get_core_local(void)
{
	uint32_t cpu_id = get_core_pos();

	/*
	 * Foreign interrupts must be disabled before playing with core_local
	 * since we otherwise may be rescheduled to a different core in the
	 * middle of this function.
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	assert(cpu_id < CFG_TEE_CORE_NB_CORE);
	return &thread_core_local[cpu_id];
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
		      uint32_t a2, uint32_t a3)
{
	thread->regs.pc = (uint32_t)thread_std_smc_entry;

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
	thread->regs.r4 = 0;
	thread->regs.r5 = 0;
	thread->regs.r6 = 0;
	thread->regs.r7 = 0;
}
#endif /*ARM32*/

#ifdef ARM64
static void init_regs(struct thread_ctx *thread, uint32_t a0, uint32_t a1,
		      uint32_t a2, uint32_t a3)
{
	thread->regs.pc = (uint64_t)thread_std_smc_entry;

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
	thread->regs.x[4] = 0;
	thread->regs.x[5] = 0;
	thread->regs.x[6] = 0;
	thread->regs.x[7] = 0;

	/* Set up frame pointer as per the Aarch64 AAPCS */
	thread->regs.x[29] = 0;
}
#endif /*ARM64*/

void thread_init_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	thread_init_threads();

	l->curr_thread = 0;
	threads[0].state = THREAD_STATE_ACTIVE;
}

void thread_clr_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread >= 0 && l->curr_thread < CFG_NUM_THREADS);
	assert(threads[l->curr_thread].state == THREAD_STATE_ACTIVE);
	threads[l->curr_thread].state = THREAD_STATE_FREE;
	l->curr_thread = -1;
}

void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)
{
	size_t n;
	struct thread_core_local *l = thread_get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == -1);

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
	init_regs(threads + n, a0, a1, a2, a3);

	thread_lazy_save_ns_vfp();
	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

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
	struct tee_ta_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (!s)
		return;

	if (s->fbuf)
		s->fbuf->syscall_trace_suspended = true;
}

static void __noprof ftrace_resume(void)
{
	struct tee_ta_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (!s)
		return;

	if (s->fbuf)
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

	assert(l->curr_thread == -1);

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

	thread_resume(&threads[n].regs);
	/*NOTREACHED*/
	panic();
}

void *thread_get_tmp_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();

	return (void *)l->tmp_stack_va_end;
}

#ifdef ARM64
vaddr_t thread_get_saved_thread_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);
	return threads[ct].kern_sp;
}
#endif /*ARM64*/

vaddr_t thread_stack_start(void)
{
	struct thread_ctx *thr;
	int ct = thread_get_id_may_fail();

	if (ct == -1)
		return 0;

	thr = threads + ct;
	return thr->stack_va_end - STACK_THREAD_SIZE;
}

size_t thread_stack_size(void)
{
	return STACK_THREAD_SIZE;
}

bool thread_is_from_abort_mode(void)
{
	struct thread_core_local *l = thread_get_core_local();

	return (l->flags >> THREAD_CLF_SAVED_SHIFT) & THREAD_CLF_ABORT;
}

#ifdef ARM32
bool thread_is_in_normal_mode(void)
{
	return (read_cpsr() & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_SVC;
}
#endif

#ifdef ARM64
bool thread_is_in_normal_mode(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	bool ret;

	/* If any bit in l->flags is set we're handling some exception. */
	ret = !l->flags;
	thread_unmask_exceptions(exceptions);

	return ret;
}
#endif

void thread_state_free(void)
{
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);

	thread_lazy_restore_ns_vfp();
	tee_pager_release_phys(
		(void *)(threads[ct].stack_va_end - STACK_THREAD_SIZE),
		STACK_THREAD_SIZE);

	thread_lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = -1;

#ifdef CFG_VIRTUALIZATION
	virt_unset_guest();
#endif
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

	assert(ct != -1);

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

	l->curr_thread = -1;

#ifdef CFG_VIRTUALIZATION
	virt_unset_guest();
#endif

	thread_unlock_global();

	return ct;
}

#ifdef ARM32
static void set_tmp_stack(struct thread_core_local *l, vaddr_t sp)
{
	l->tmp_stack_va_end = sp;
	thread_set_irq_sp(sp);
	thread_set_fiq_sp(sp);
}

static void set_abt_stack(struct thread_core_local *l, vaddr_t sp)
{
	l->abt_stack_va_end = sp;
	thread_set_abt_sp((vaddr_t)l);
	thread_set_und_sp((vaddr_t)l);
}
#endif /*ARM32*/

#ifdef ARM64
static void set_tmp_stack(struct thread_core_local *l, vaddr_t sp)
{
	/*
	 * We're already using the tmp stack when this function is called
	 * so there's no need to assign it to any stack pointer. However,
	 * we'll need to restore it at different times so store it here.
	 */
	l->tmp_stack_va_end = sp;
}

static void set_abt_stack(struct thread_core_local *l, vaddr_t sp)
{
	l->abt_stack_va_end = sp;
}
#endif /*ARM64*/

bool thread_init_stack(uint32_t thread_id, vaddr_t sp)
{
	if (thread_id >= CFG_NUM_THREADS)
		return false;
	threads[thread_id].stack_va_end = sp;
	return true;
}

int thread_get_id_may_fail(void)
{
	/*
	 * thread_get_core_local() requires foreign interrupts to be disabled
	 */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	int ct = l->curr_thread;

	thread_unmask_exceptions(exceptions);
	return ct;
}

int thread_get_id(void)
{
	int ct = thread_get_id_may_fail();

	assert(ct >= 0 && ct < CFG_NUM_THREADS);
	return ct;
}

static void init_handlers(const struct thread_handlers *handlers)
{
	thread_cpu_on_handler_ptr = handlers->cpu_on;
	thread_cpu_off_handler_ptr = handlers->cpu_off;
	thread_cpu_suspend_handler_ptr = handlers->cpu_suspend;
	thread_cpu_resume_handler_ptr = handlers->cpu_resume;
	thread_system_off_handler_ptr = handlers->system_off;
	thread_system_reset_handler_ptr = handlers->system_reset;
}

#ifdef CFG_WITH_PAGER
static void init_thread_stacks(void)
{
	size_t n = 0;

	/*
	 * Allocate virtual memory for thread stacks.
	 */
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		tee_mm_entry_t *mm = NULL;
		vaddr_t sp = 0;
		size_t num_pages = 0;
		struct fobj *fobj = NULL;

		/* Find vmem for thread stack and its protection gap */
		mm = tee_mm_alloc(&tee_mm_vcore,
				  SMALL_PAGE_SIZE + STACK_THREAD_SIZE);
		assert(mm);

		/* Claim eventual physical page */
		tee_pager_add_pages(tee_mm_get_smem(mm), tee_mm_get_size(mm),
				    true);

		num_pages = tee_mm_get_bytes(mm) / SMALL_PAGE_SIZE - 1;
		fobj = fobj_locked_paged_alloc(num_pages);

		/* Add the area to the pager */
		tee_pager_add_core_area(tee_mm_get_smem(mm) + SMALL_PAGE_SIZE,
					PAGER_AREA_TYPE_LOCK, fobj);
		fobj_put(fobj);

		/* init effective stack */
		sp = tee_mm_get_smem(mm) + tee_mm_get_bytes(mm);
		asan_tag_access((void *)tee_mm_get_smem(mm), (void *)sp);
		if (!thread_init_stack(n, sp))
			panic("init stack failed");
	}
}
#else
static void init_thread_stacks(void)
{
	size_t n;

	/* Assign the thread stacks */
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		if (!thread_init_stack(n, GET_STACK(stack_thread[n])))
			panic("thread_init_stack failed");
	}
}
#endif /*CFG_WITH_PAGER*/

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

#if defined(CFG_CORE_WORKAROUND_SPECTRE_BP_SEC) && defined(ARM64)
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

void thread_init_threads(void)
{
	size_t n;

	init_thread_stacks();
	pgt_init();

	mutex_lockdep_init();

	for (n = 0; n < CFG_NUM_THREADS; n++) {
		TAILQ_INIT(&threads[n].tsd.sess_stack);
		SLIST_INIT(&threads[n].tsd.pgt_cache);
	}

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
		thread_core_local[n].curr_thread = -1;
}

void thread_init_primary(const struct thread_handlers *handlers)
{
	init_handlers(handlers);

	/* Initialize canaries around the stacks */
	init_canaries();

	init_user_kcode();
}

static void init_sec_mon(size_t pos __maybe_unused)
{
#if !defined(CFG_WITH_ARM_TRUSTED_FW)
	/* Initialize secure monitor */
	sm_init(GET_STACK(stack_tmp[pos]));
#endif
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

#ifdef ARM64
static bool probe_workaround_available(void)
{
	int32_t r;

	r = thread_smc(SMCCC_VERSION, 0, 0, 0);
	if (r < 0)
		return false;
	if (r < 0x10001)	/* compare with version 1.1 */
		return false;

	/* Version >= 1.1, so SMCCC_ARCH_FEATURES is available */
	r = thread_smc(SMCCC_ARCH_FEATURES, SMCCC_ARCH_WORKAROUND_1, 0, 0);
	return r >= 0;
}

static vaddr_t __maybe_unused select_vector(vaddr_t a)
{
	if (probe_workaround_available()) {
		DMSG("SMCCC_ARCH_WORKAROUND_1 (%#08" PRIx32 ") available",
		     SMCCC_ARCH_WORKAROUND_1);
		DMSG("SMC Workaround for CVE-2017-5715 used");
		return a;
	}

	DMSG("SMCCC_ARCH_WORKAROUND_1 (%#08" PRIx32 ") unavailable",
	     SMCCC_ARCH_WORKAROUND_1);
	DMSG("SMC Workaround for CVE-2017-5715 not needed (if ARM-TF is up to date)");
	return (vaddr_t)thread_excp_vect;
}
#else
static vaddr_t __maybe_unused select_vector(vaddr_t a)
{
	return a;
}
#endif

static vaddr_t get_excp_vect(void)
{
#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
	uint32_t midr = read_midr();

	if (get_midr_implementer(midr) != MIDR_IMPLEMENTER_ARM)
		return (vaddr_t)thread_excp_vect;

	switch (get_midr_primary_part(midr)) {
#ifdef ARM32
	case CORTEX_A8_PART_NUM:
	case CORTEX_A9_PART_NUM:
	case CORTEX_A17_PART_NUM:
#endif
	case CORTEX_A57_PART_NUM:
	case CORTEX_A72_PART_NUM:
	case CORTEX_A73_PART_NUM:
	case CORTEX_A75_PART_NUM:
		return select_vector((vaddr_t)thread_excp_vect_workaround);
#ifdef ARM32
	case CORTEX_A15_PART_NUM:
		return select_vector((vaddr_t)thread_excp_vect_workaround_a15);
#endif
	default:
		return (vaddr_t)thread_excp_vect;
	}
#endif /*CFG_CORE_WORKAROUND_SPECTRE_BP_SEC*/

	return (vaddr_t)thread_excp_vect;
}

void thread_init_per_cpu(void)
{
	size_t pos = get_core_pos();
	struct thread_core_local *l = thread_get_core_local();

	init_sec_mon(pos);

	set_tmp_stack(l, GET_STACK(stack_tmp[pos]) - STACK_TMP_OFFS);
	set_abt_stack(l, GET_STACK(stack_abt[pos]));

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

struct thread_specific_data *thread_get_tsd(void)
{
	return &threads[thread_get_id()].tsd;
}

struct thread_ctx_regs *thread_get_ctx_regs(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread != -1);
	return &threads[l->curr_thread].regs;
}

void thread_set_foreign_intr(bool enable)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != -1);

	if (enable) {
		threads[l->curr_thread].flags |=
					THREAD_FLAGS_FOREIGN_INTR_ENABLE;
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
	} else {
		/*
		 * No need to disable foreign interrupts here since they're
		 * already disabled above.
		 */
		threads[l->curr_thread].flags &=
					~THREAD_FLAGS_FOREIGN_INTR_ENABLE;
	}
}

void thread_restore_foreign_intr(void)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != -1);

	if (threads[l->curr_thread].flags & THREAD_FLAGS_FOREIGN_INTR_ENABLE)
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
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

void thread_user_clear_vfp(struct thread_user_vfp_state *uvfp)
{
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
			 uint32_t spsr)
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
	/* Set frame pointer (user stack can't be unwound past this point) */
	regs->x[29] = 0;
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

	tee_ta_update_session_utime_resume();

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
	set_ctx_regs(regs, a0, a1, a2, a3, user_sp, entry_func, spsr);
	rc = __thread_enter_user_mode(regs, exit_status0, exit_status1);
	thread_unmask_exceptions(exceptions);
	return rc;
}

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
			   vaddr_t *va, size_t *sz)
{
	core_mmu_get_user_va_range(va, NULL);
	*mobj = mobj_tee_ram;
	*offset = thread_user_kcode_va - VCORE_START_VA;
	*sz = thread_user_kcode_size;
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
	*mobj = mobj_tee_ram;
	*offset = (vaddr_t)thread_user_kdata_page - VCORE_START_VA;
	*sz = sizeof(thread_user_kdata_page);
}
#endif

static void setup_unwind_user_mode(struct thread_svc_regs *regs)
{
#ifdef ARM32
	regs->lr = (uintptr_t)thread_unwind_user_mode;
	regs->spsr = read_cpsr();
#endif
#ifdef ARM64
	regs->elr = (uintptr_t)thread_unwind_user_mode;
	regs->spsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0, 0);
	regs->spsr |= read_daif();
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

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak thread_svc_handler(struct thread_svc_regs *regs)
{
	struct tee_ta_session *sess = NULL;
	uint32_t state = 0;

	/* Enable native interrupts */
	state = thread_get_exceptions();
	thread_unmask_exceptions(state & ~THREAD_EXCP_NATIVE_INTR);

	thread_user_save_vfp();

	/* TA has just entered kernel mode */
	tee_ta_update_session_utime_suspend();

	/* Restore foreign interrupts which are disabled on exception entry */
	thread_restore_foreign_intr();

	tee_ta_get_current_session(&sess);
	assert(sess && sess->ctx->ops && sess->ctx->ops->handle_svc);
	if (sess->ctx->ops->handle_svc(regs)) {
		/* We're about to switch back to user mode */
		tee_ta_update_session_utime_resume();
	} else {
		/* We're returning from __thread_enter_user_mode() */
		setup_unwind_user_mode(regs);
	}
}
