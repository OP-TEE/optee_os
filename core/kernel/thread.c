// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2022, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2020-2021, Arm Limited
 */

#include <config.h>
#include <crypto/crypto.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/lockdep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <mm/mobj.h>
#include <mm/page_alloc.h>
#include <stdalign.h>

#if defined(CFG_DYN_CONFIG)
struct thread_core_local *thread_core_local __nex_bss;
size_t thread_core_count __nex_bss;
struct thread_ctx *threads;
size_t thread_count;
#else
static struct thread_core_local
	__thread_core_local[CFG_TEE_CORE_NB_CORE] __nex_bss;
struct thread_core_local *thread_core_local __nex_data = __thread_core_local;
size_t thread_core_count __nex_data = CFG_TEE_CORE_NB_CORE;
static struct thread_ctx __threads[CFG_NUM_THREADS];
struct thread_ctx *threads = __threads;
size_t thread_count = CFG_NUM_THREADS;
#endif
unsigned long thread_core_local_pa __nex_bss;
struct thread_core_local *__thread_core_local_new __nex_bss;
size_t __thread_core_count_new __nex_bss;

/*
 * Stacks
 *
 * [Lower addresses on the left]
 *
 * [ STACK_CANARY_SIZE/2 | STACK_CHECK_EXTRA | STACK_XXX_SIZE | STACK_CANARY_SIZE/2 ]
 * ^                     ^                   ^                ^
 * stack_xxx[n]          "hard" top          "soft" top       bottom
 */

static uint32_t start_canary_value = 0xdedede00;
static uint32_t end_canary_value = 0xababab00;

#define DECLARE_STACK(name, num_stacks, stack_size, linkage) \
linkage uint32_t name[num_stacks] \
		[ROUNDUP(stack_size + STACK_CANARY_SIZE + STACK_CHECK_EXTRA, \
			 STACK_ALIGNMENT) / sizeof(uint32_t)] \
		__attribute__((section(".nozi_stack." # name), \
			       aligned(STACK_ALIGNMENT)))

#ifndef CFG_DYN_CONFIG
DECLARE_STACK(stack_tmp, CFG_TEE_CORE_NB_CORE, STACK_TMP_SIZE,
	      /* global linkage */);
DECLARE_STACK(stack_abt, CFG_TEE_CORE_NB_CORE, STACK_ABT_SIZE, static);
#define GET_STACK_BOTTOM(stack, n) ((vaddr_t)&(stack)[n] + sizeof(stack[n]) - \
				    STACK_CANARY_SIZE / 2)
#else
/* Not used */
#define GET_STACK_BOTTOM(stack, n) 0
#endif

#if defined(CFG_DYN_CONFIG) || defined(CFG_WITH_PAGER)
/* Not used */
#define GET_STACK_THREAD_BOTTOM(n) 0
#else
DECLARE_STACK(stack_thread, CFG_NUM_THREADS, STACK_THREAD_SIZE, static);
#define GET_STACK_THREAD_BOTTOM(n) \
	((vaddr_t)&stack_thread[n] +  sizeof(stack_thread[n]) - \
	 STACK_CANARY_SIZE / 2)
#endif

#ifndef CFG_DYN_CONFIG
const uint32_t stack_tmp_stride __section(".identity_map.stack_tmp_stride") =
	sizeof(stack_tmp[0]);

/*
 * This stack setup info is required by secondary boot cores before they
 * each locally enable the pager (the mmu). Hence kept in pager sections.
 */
DECLARE_KEEP_PAGER(stack_tmp_stride);
#endif

static unsigned int thread_global_lock __nex_bss = SPINLOCK_UNLOCK;

static size_t stack_size_to_alloc_size(size_t stack_size)
{
	return ROUNDUP(stack_size + STACK_CANARY_SIZE + STACK_CHECK_EXTRA,
		       STACK_ALIGNMENT);
}

static vaddr_t stack_end_va_to_top_hard(size_t stack_size, vaddr_t end_va)
{
	size_t l = stack_size_to_alloc_size(stack_size);

	return end_va - l + STACK_CANARY_SIZE;
}

static vaddr_t stack_end_va_to_top_soft(size_t stack_size, vaddr_t end_va)
{
	return stack_end_va_to_top_hard(stack_size, end_va) + STACK_CHECK_EXTRA;
}

static vaddr_t stack_end_va_to_bottom(size_t stack_size __unused,
				      vaddr_t end_va)
{
	return end_va;
}

static uint32_t *stack_end_va_to_start_canary(size_t stack_size, vaddr_t end_va)
{
	return (uint32_t *)(stack_end_va_to_top_hard(stack_size, end_va) -
			    STACK_CANARY_SIZE / 2);
}

static uint32_t *stack_end_va_to_end_canary(size_t stack_size __unused,
					    vaddr_t end_va)
{
	return (uint32_t *)(end_va + STACK_CANARY_SIZE / 2 - sizeof(uint32_t));
}

static void init_canaries(size_t stack_size, vaddr_t va_end)
{
	uint32_t *canary = NULL;

	assert(va_end);
	canary = stack_end_va_to_start_canary(stack_size, va_end);
	*canary = start_canary_value;
	canary = stack_end_va_to_end_canary(stack_size, va_end);
	*canary = end_canary_value;
}

void thread_init_canaries(void)
{
	vaddr_t va = 0;
	size_t n = 0;

	if (IS_ENABLED(CFG_WITH_STACK_CANARIES)) {
		for (n = 0; n < thread_core_count; n++) {
			if (thread_core_local[n].tmp_stack_va_end) {
				va = thread_core_local[n].tmp_stack_va_end +
				     STACK_TMP_OFFS;
				init_canaries(STACK_TMP_SIZE, va);
			}
			va = thread_core_local[n].abt_stack_va_end;
			if (va)
				init_canaries(STACK_ABT_SIZE, va);
		}

	}

	if (IS_ENABLED(CFG_WITH_STACK_CANARIES) &&
	    !IS_ENABLED(CFG_WITH_PAGER) &&
	    !IS_ENABLED(CFG_NS_VIRTUALIZATION) && threads) {
		for (n = 0; n < thread_count; n++) {
			va = threads[n].stack_va_end;
			if (va)
				init_canaries(STACK_THREAD_SIZE, va);
		}
	}
}

#if defined(CFG_WITH_STACK_CANARIES)
void thread_update_canaries(void)
{
	uint32_t canary[2] = { };
	uint32_t exceptions = 0;

	plat_get_random_stack_canaries(canary, ARRAY_SIZE(canary),
				       sizeof(canary[0]));

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	thread_check_canaries();

	start_canary_value = canary[0];
	end_canary_value = canary[1];
	thread_init_canaries();

	thread_unmask_exceptions(exceptions);
}
#endif

static void check_stack_canary(const char *stack_name __maybe_unused,
			       size_t n __maybe_unused,
			       size_t stack_size, vaddr_t end_va)
{
	uint32_t *canary = NULL;

	canary = stack_end_va_to_start_canary(stack_size, end_va);
	if (*canary != start_canary_value) {
		EMSG_RAW("Dead canary at start of '%s[%zu]' (%p)",
			 stack_name, n, (void *)canary);
		panic();
	}

	canary = stack_end_va_to_end_canary(stack_size, end_va);
	if (*canary != end_canary_value) {
		EMSG_RAW("Dead canary at end of '%s[%zu]' (%p)",
			 stack_name, n, (void *)canary);
		panic();
	}
}

void thread_check_canaries(void)
{
	vaddr_t va = 0;
	size_t n = 0;

	if (IS_ENABLED(CFG_WITH_STACK_CANARIES)) {
		for (n = 0; n < thread_core_count; n++) {
			if (thread_core_local[n].tmp_stack_va_end) {
				va = thread_core_local[n].tmp_stack_va_end +
				     STACK_TMP_OFFS;
				check_stack_canary("tmp_stack", n,
						   STACK_TMP_SIZE, va);
			}

			va = thread_core_local[n].abt_stack_va_end;
			if (va)
				check_stack_canary("abt_stack", n,
						   STACK_ABT_SIZE, va);
		}
	}

	if (IS_ENABLED(CFG_WITH_STACK_CANARIES) &&
	    !IS_ENABLED(CFG_WITH_PAGER) && !IS_ENABLED(CFG_NS_VIRTUALIZATION)) {
		for (n = 0; n < thread_count; n++) {
			va = threads[n].stack_va_end;
			if (va)
				check_stack_canary("thread_stack", n,
						   STACK_THREAD_SIZE, va);
		}
	}
}

void thread_lock_global(void)
{
	cpu_spin_lock(&thread_global_lock);
}

void thread_unlock_global(void)
{
	cpu_spin_unlock(&thread_global_lock);
}

static struct thread_core_local * __nostackcheck
get_core_local(unsigned int pos)
{
	/*
	 * Foreign interrupts must be disabled before playing with core_local
	 * since we otherwise may be rescheduled to a different core in the
	 * middle of this function.
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	/*
	 * We boot on a single core and have allocated only one struct
	 * thread_core_local so we return that regardless of pos.
	 */
	if (IS_ENABLED(CFG_DYN_CONFIG) &&
	    thread_core_local != __thread_core_local_new)
		return thread_core_local;

	assert(pos < thread_core_count);
	return &thread_core_local[pos];
}

struct thread_core_local * __nostackcheck thread_get_core_local(void)
{
	unsigned int pos = get_core_pos();

	return get_core_local(pos);
}

#ifdef CFG_CORE_DEBUG_CHECK_STACKS
static void print_stack_limits(void)
{
	size_t n = 0;
	vaddr_t __maybe_unused start = 0;
	vaddr_t __maybe_unused end = 0;
	vaddr_t va = 0;

	for (n = 0; n < thread_core_count; n++) {
		va = thread_core_local[n].tmp_stack_va_end + STACK_TMP_OFFS;
		start = stack_end_va_to_top_soft(STACK_TMP_SIZE, va);
		end = stack_end_va_to_bottom(STACK_TMP_SIZE, va);
		DMSG("tmp [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);

		va = thread_core_local[n].abt_stack_va_end;
		start = stack_end_va_to_top_soft(STACK_ABT_SIZE, va);
		end = stack_end_va_to_bottom(STACK_ABT_SIZE, va);
		DMSG("abt [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);
	}

	for (n = 0; n < thread_count; n++) {
		va = threads[n].stack_va_end;
		start = stack_end_va_to_top_soft(STACK_THREAD_SIZE, va);
		end = stack_end_va_to_bottom(STACK_THREAD_SIZE, va);
		DMSG("thr [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);
	}
}

static void check_stack_limits(void)
{
	vaddr_t stack_start = 0;
	vaddr_t stack_end = 0;
	/* Any value in the current stack frame will do */
	vaddr_t current_sp = (vaddr_t)&stack_start;

	if (!get_stack_soft_limits(&stack_start, &stack_end))
		panic("Unknown stack limits");
	if (current_sp < stack_start || current_sp > stack_end) {
		EMSG("Stack pointer out of range: 0x%" PRIxVA " not in [0x%"
		     PRIxVA " .. 0x%" PRIxVA "]", current_sp, stack_start,
		     stack_end);
		print_stack_limits();
		panic();
	}
}

static bool * __nostackcheck get_stackcheck_recursion_flag(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	unsigned int pos = get_core_pos();
	struct thread_core_local *l = get_core_local(pos);
	int ct = l->curr_thread;
	bool *p = NULL;

	if (l->flags & (THREAD_CLF_ABORT | THREAD_CLF_TMP))
		p = &l->stackcheck_recursion;
	else if (!l->flags)
		p = &threads[ct].tsd.stackcheck_recursion;

	thread_unmask_exceptions(exceptions);
	return p;
}

void __cyg_profile_func_enter(void *this_fn, void *call_site);
void __nostackcheck __cyg_profile_func_enter(void *this_fn __unused,
					     void *call_site __unused)
{
	bool *p = get_stackcheck_recursion_flag();

	assert(p);
	if (*p)
		return;
	*p = true;
	check_stack_limits();
	*p = false;
}

void __cyg_profile_func_exit(void *this_fn, void *call_site);
void __nostackcheck __cyg_profile_func_exit(void *this_fn __unused,
					    void *call_site __unused)
{
}
#else
static void print_stack_limits(void)
{
}
#endif

void thread_init_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	l->curr_thread = 0;
	threads[0].state = THREAD_STATE_ACTIVE;
}

void __nostackcheck thread_clr_boot_thread(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread >= 0 && l->curr_thread < CFG_NUM_THREADS);
	assert(threads[l->curr_thread].state == THREAD_STATE_ACTIVE);
	threads[l->curr_thread].state = THREAD_STATE_FREE;
	l->curr_thread = THREAD_ID_INVALID;
	print_stack_limits();
}

void __nostackcheck *thread_get_tmp_sp(void)
{
	struct thread_core_local *l = thread_get_core_local();

	/*
	 * Called from assembly when switching to the temporary stack, so flags
	 * need updating
	 */
	l->flags |= THREAD_CLF_TMP;

	return (void *)l->tmp_stack_va_end;
}

vaddr_t thread_stack_start(void)
{
	struct thread_ctx *thr;
	int ct = thread_get_id_may_fail();

	if (ct == THREAD_ID_INVALID)
		return 0;

	thr = threads + ct;
	return stack_end_va_to_top_soft(STACK_THREAD_SIZE, thr->stack_va_end);
}

size_t thread_stack_size(void)
{
	return STACK_THREAD_SIZE;
}

bool get_stack_limits(vaddr_t *start, vaddr_t *end, bool hard)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	unsigned int pos = get_core_pos();
	struct thread_core_local *l = get_core_local(pos);
	int ct = l->curr_thread;
	size_t stack_size = 0;
	bool ret = true;
	vaddr_t va = 0;

	if (l->flags & THREAD_CLF_TMP) {
		va = l->tmp_stack_va_end + STACK_TMP_OFFS;
		stack_size = STACK_TMP_SIZE;
	} else if (l->flags & THREAD_CLF_ABORT) {
		va = l->abt_stack_va_end;
		stack_size = STACK_ABT_SIZE;
	} else if (!l->flags && ct >= 0 && (size_t)ct < thread_count) {
		va = threads[ct].stack_va_end;
		stack_size = STACK_THREAD_SIZE;
	} else {
		ret = false;
		goto out;
	}

	*end = stack_end_va_to_bottom(stack_size, va);
	if (hard)
		*start = stack_end_va_to_top_hard(stack_size, va);
	else
		*start = stack_end_va_to_top_soft(stack_size, va);
out:
	thread_unmask_exceptions(exceptions);
	return ret;
}

bool thread_is_from_abort_mode(void)
{
	struct thread_core_local *l = thread_get_core_local();

	return (l->flags >> THREAD_CLF_SAVED_SHIFT) & THREAD_CLF_ABORT;
}

/*
 * This function should always be accurate, but it might be possible to
 * implement a more efficient depending on cpu architecture.
 */
bool __weak __noprof thread_is_in_normal_mode(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	bool ret;

	/*
	 * If any bit in l->flags is set aside from THREAD_CLF_TMP we're
	 * handling some exception.
	 */
	ret = (l->curr_thread != THREAD_ID_INVALID) &&
	      !(l->flags & ~THREAD_CLF_TMP);
	thread_unmask_exceptions(exceptions);

	return ret;
}

short int __noprof thread_get_id_may_fail(void)
{
	/*
	 * thread_get_core_local() requires foreign interrupts to be disabled
	 */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l = thread_get_core_local();
	short int ct = l->curr_thread;

	thread_unmask_exceptions(exceptions);
	return ct;
}

short int __noprof thread_get_id(void)
{
	short int ct = thread_get_id_may_fail();

	/* Thread ID has to fit in a short int */
	COMPILE_TIME_ASSERT(CFG_NUM_THREADS <= SHRT_MAX);
	assert(ct >= 0 && ct < CFG_NUM_THREADS);
	return ct;
}

static vaddr_t alloc_stack(size_t stack_size, bool nex)
{
	size_t l = stack_size_to_alloc_size(stack_size);
	size_t rl = ROUNDUP(l, SMALL_PAGE_SIZE);
	uint32_t flags = MAF_GUARD_HEAD;
	vaddr_t end_va = 0;
	vaddr_t va = 0;

	if (nex)
		flags |= MAF_NEX;
	va = virt_page_alloc(rl / SMALL_PAGE_SIZE, flags);
	if (!va)
		panic();

	end_va = va + l - STACK_CANARY_SIZE / 2;
	if (IS_ENABLED(CFG_WITH_STACK_CANARIES))
		init_canaries(stack_size, end_va);

	return end_va;
}

#ifdef CFG_WITH_PAGER
static void init_thread_stacks(void)
{
	size_t n = 0;

	/*
	 * Allocate virtual memory for thread stacks.
	 */
	for (n = 0; n < thread_count; n++) {
		tee_mm_entry_t *mm = NULL;
		vaddr_t sp = 0;
		size_t num_pages = 0;
		struct fobj *fobj = NULL;

		/* Find vmem for thread stack and its protection gap */
		mm = tee_mm_alloc(&core_virt_mem_pool,
				  SMALL_PAGE_SIZE + STACK_THREAD_SIZE);
		assert(mm);

		/* Claim eventual physical page */
		tee_pager_add_pages(tee_mm_get_smem(mm), tee_mm_get_size(mm),
				    true);

		num_pages = tee_mm_get_bytes(mm) / SMALL_PAGE_SIZE - 1;
		fobj = fobj_locked_paged_alloc(num_pages);

		/* Add the region to the pager */
		tee_pager_add_core_region(tee_mm_get_smem(mm) + SMALL_PAGE_SIZE,
					  PAGED_REGION_TYPE_LOCK, fobj);
		fobj_put(fobj);

		/* init effective stack */
		sp = tee_mm_get_smem(mm) + tee_mm_get_bytes(mm);
		asan_tag_access((void *)tee_mm_get_smem(mm), (void *)sp);
		threads[n].stack_va_end = sp;
	}
}
#else
static void init_thread_stacks(void)
{
	vaddr_t va = 0;
	size_t n = 0;

	/* Assign the thread stacks */
	for (n = 0; n < thread_count; n++) {
		if (IS_ENABLED(CFG_DYN_CONFIG))
			va = alloc_stack(STACK_THREAD_SIZE, false);
		else
			va = GET_STACK_THREAD_BOTTOM(n);
		threads[n].stack_va_end = va;
		if (IS_ENABLED(CFG_WITH_STACK_CANARIES))
			init_canaries(STACK_THREAD_SIZE, va);
	}
}
#endif /*CFG_WITH_PAGER*/

static struct thread_ctx *swap_thread_ctx(struct thread_ctx *thr, size_t count)
{
	struct thread_ctx *t = threads;

	if (!thr)
		panic();
	threads = thr;
	thread_count = count;

	return t;
}
DECLARE_KEEP_PAGER(swap_thread_ctx);

void thread_init_threads(size_t count)
{
	size_t n = 0;

	if (IS_ENABLED(CFG_DYN_CONFIG)) {
		assert(count <= CFG_NUM_THREADS);
		free(swap_thread_ctx(calloc(count, sizeof(*threads)), count));
	} else {
		assert(count == CFG_NUM_THREADS);
	}

	init_thread_stacks();
	print_stack_limits();
	pgt_init();

	mutex_lockdep_init();

	for (n = 0; n < thread_count; n++)
		TAILQ_INIT(&threads[n].tsd.sess_stack);
}

#ifndef CFG_DYN_CONFIG
vaddr_t __nostackcheck thread_get_abt_stack(void)
{
	return GET_STACK_BOTTOM(stack_abt, get_core_pos());
}
#endif

void thread_init_thread_core_local(size_t core_count)
{
	struct thread_core_local *tcl = NULL;
	const size_t core_pos = get_core_pos();
	vaddr_t va = 0;
	size_t n = 0;

	if (IS_ENABLED(CFG_DYN_CONFIG)) {
		assert(core_count <= CFG_TEE_CORE_NB_CORE);
		tcl = nex_calloc(core_count, sizeof(*tcl));
		if (!tcl)
			panic();
		__thread_core_local_new = tcl;
		__thread_core_count_new = core_count;
	} else {
		tcl = thread_core_local;
		assert(core_count == CFG_TEE_CORE_NB_CORE);

		for (n = 0; n < thread_core_count; n++) {
			init_canaries(STACK_TMP_SIZE,
				      GET_STACK_BOTTOM(stack_tmp, n));
			init_canaries(STACK_ABT_SIZE,
				      GET_STACK_BOTTOM(stack_abt, n));
		}
	}

	for (n = 0; n < core_count; n++) {
		if (n == core_pos) {
			if (IS_ENABLED(CFG_DYN_CONFIG))
				tcl[n] = thread_core_local[0];
			else
				continue;
		} else {
			tcl[n].curr_thread = THREAD_ID_INVALID;
			tcl[n].flags = THREAD_CLF_TMP;
		}

		if (IS_ENABLED(CFG_DYN_CONFIG))
			va = alloc_stack(STACK_TMP_SIZE, true);
		else
			va = GET_STACK_BOTTOM(stack_tmp, n);
		tcl[n].tmp_stack_va_end = va - STACK_TMP_OFFS;
#ifdef ARM32
		tcl[n].tmp_stack_pa_end =
			vaddr_to_phys(tcl[n].tmp_stack_va_end);
#endif

		if (IS_ENABLED(CFG_DYN_CONFIG))
			va = alloc_stack(STACK_ABT_SIZE, true);
		else
			va = GET_STACK_BOTTOM(stack_abt, n);
		tcl[n].abt_stack_va_end = va;
	}
}

#if defined(CFG_CORE_PAUTH)
void thread_init_thread_pauth_keys(void)
{
	size_t n = 0;

	for (n = 0; n < thread_count; n++)
		if (crypto_rng_read(&threads[n].keys, sizeof(threads[n].keys)))
			panic("Failed to init thread pauth keys");
}

void thread_init_core_local_pauth_keys(void)
{
	struct thread_core_local *tcl = thread_core_local;
	size_t n = 0;

	for (n = 0; n < thread_core_count; n++)
		if (crypto_rng_read(&tcl[n].keys, sizeof(tcl[n].keys)))
			panic("Failed to init core local pauth keys");
}
#endif

struct thread_specific_data * __noprof thread_get_tsd(void)
{
	return &threads[thread_get_id()].tsd;
}

struct thread_ctx_regs * __nostackcheck thread_get_ctx_regs(void)
{
	struct thread_core_local *l = thread_get_core_local();

	assert(l->curr_thread != THREAD_ID_INVALID);
	return &threads[l->curr_thread].regs;
}

void thread_set_foreign_intr(bool enable)
{
	/* thread_get_core_local() requires foreign interrupts to be disabled */
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_FOREIGN_INTR);
	struct thread_core_local *l;

	l = thread_get_core_local();

	assert(l->curr_thread != THREAD_ID_INVALID);

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

	assert(l->curr_thread != THREAD_ID_INVALID);

	if (threads[l->curr_thread].flags & THREAD_FLAGS_FOREIGN_INTR_ENABLE)
		thread_set_exceptions(exceptions & ~THREAD_EXCP_FOREIGN_INTR);
}

static struct mobj *alloc_shm(enum thread_shm_type shm_type, size_t size)
{
	switch (shm_type) {
	case THREAD_SHM_TYPE_APPLICATION:
		return thread_rpc_alloc_payload(size);
	case THREAD_SHM_TYPE_KERNEL_PRIVATE:
		return thread_rpc_alloc_kernel_payload(size);
	case THREAD_SHM_TYPE_GLOBAL:
		return thread_rpc_alloc_global_payload(size);
	default:
		return NULL;
	}
}

static void clear_shm_cache_entry(struct thread_shm_cache_entry *ce)
{
	if (ce->mobj) {
		switch (ce->type) {
		case THREAD_SHM_TYPE_APPLICATION:
			thread_rpc_free_payload(ce->mobj);
			break;
		case THREAD_SHM_TYPE_KERNEL_PRIVATE:
			thread_rpc_free_kernel_payload(ce->mobj);
			break;
		case THREAD_SHM_TYPE_GLOBAL:
			thread_rpc_free_global_payload(ce->mobj);
			break;
		default:
			assert(0); /* "can't happen" */
			break;
		}
	}
	ce->mobj = NULL;
	ce->size = 0;
}

static struct thread_shm_cache_entry *
get_shm_cache_entry(enum thread_shm_cache_user user)
{
	struct thread_shm_cache *cache = &threads[thread_get_id()].shm_cache;
	struct thread_shm_cache_entry *ce = NULL;

	SLIST_FOREACH(ce, cache, link)
		if (ce->user == user)
			return ce;

	ce = calloc(1, sizeof(*ce));
	if (ce) {
		ce->user = user;
		SLIST_INSERT_HEAD(cache, ce, link);
	}

	return ce;
}

void *thread_rpc_shm_cache_alloc(enum thread_shm_cache_user user,
				 enum thread_shm_type shm_type,
				 size_t size, struct mobj **mobj)
{
	struct thread_shm_cache_entry *ce = NULL;
	size_t sz = size;
	paddr_t p = 0;
	void *va = NULL;

	if (!size)
		return NULL;

	ce = get_shm_cache_entry(user);
	if (!ce)
		return NULL;

	/*
	 * Always allocate in page chunks as normal world allocates payload
	 * memory as complete pages.
	 */
	sz = ROUNDUP(size, SMALL_PAGE_SIZE);

	if (ce->type != shm_type || sz > ce->size) {
		clear_shm_cache_entry(ce);

		ce->mobj = alloc_shm(shm_type, sz);
		if (!ce->mobj)
			return NULL;

		if (mobj_get_pa(ce->mobj, 0, 0, &p))
			goto err;

		if (!IS_ALIGNED_WITH_TYPE(p, uint64_t))
			goto err;

		va = mobj_get_va(ce->mobj, 0, sz);
		if (!va)
			goto err;

		ce->size = sz;
		ce->type = shm_type;
	} else {
		va = mobj_get_va(ce->mobj, 0, sz);
		if (!va)
			goto err;
	}
	*mobj = ce->mobj;

	return va;
err:
	clear_shm_cache_entry(ce);
	return NULL;
}

void thread_rpc_shm_cache_clear(struct thread_shm_cache *cache)
{
	while (true) {
		struct thread_shm_cache_entry *ce = SLIST_FIRST(cache);

		if (!ce)
			break;
		SLIST_REMOVE_HEAD(cache, link);
		clear_shm_cache_entry(ce);
		free(ce);
	}
}
