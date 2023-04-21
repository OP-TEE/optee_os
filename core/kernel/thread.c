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

struct thread_ctx threads[CFG_NUM_THREADS];

struct thread_core_local thread_core_local[CFG_TEE_CORE_NB_CORE] __nex_bss;

/*
 * Stacks
 *
 * [Lower addresses on the left]
 *
 * [ STACK_CANARY_SIZE/2 | STACK_CHECK_EXTRA | STACK_XXX_SIZE | STACK_CANARY_SIZE/2 ]
 * ^                     ^                   ^                ^
 * stack_xxx[n]          "hard" top          "soft" top       bottom
 */

#ifdef CFG_WITH_STACK_CANARIES
static uint32_t start_canary_value = 0xdedede00;
static uint32_t end_canary_value = 0xababab00;
#define GET_START_CANARY(name, stack_num) name[stack_num][0]
#define GET_END_CANARY(name, stack_num) \
	name[stack_num][sizeof(name[stack_num]) / sizeof(uint32_t) - 1]
#endif

#define DECLARE_STACK(name, num_stacks, stack_size, linkage) \
linkage uint32_t name[num_stacks] \
		[ROUNDUP(stack_size + STACK_CANARY_SIZE + STACK_CHECK_EXTRA, \
			 STACK_ALIGNMENT) / sizeof(uint32_t)] \
		__attribute__((section(".nozi_stack." # name), \
			       aligned(STACK_ALIGNMENT)))

#define GET_STACK(stack) ((vaddr_t)(stack) + STACK_SIZE(stack))

DECLARE_STACK(stack_tmp, CFG_TEE_CORE_NB_CORE, STACK_TMP_SIZE,
	      /* global linkage */);
DECLARE_STACK(stack_abt, CFG_TEE_CORE_NB_CORE, STACK_ABT_SIZE, static);
#ifndef CFG_WITH_PAGER
DECLARE_STACK(stack_thread, CFG_NUM_THREADS, STACK_THREAD_SIZE, static);
#endif

#define GET_STACK_TOP_HARD(stack, n) \
	((vaddr_t)&(stack)[n] + STACK_CANARY_SIZE / 2)
#define GET_STACK_TOP_SOFT(stack, n) \
	(GET_STACK_TOP_HARD(stack, n) + STACK_CHECK_EXTRA)
#define GET_STACK_BOTTOM(stack, n) ((vaddr_t)&(stack)[n] + sizeof(stack[n]) - \
				    STACK_CANARY_SIZE / 2)

const uint32_t stack_tmp_stride __section(".identity_map.stack_tmp_stride") =
	sizeof(stack_tmp[0]);

/*
 * This stack setup info is required by secondary boot cores before they
 * each locally enable the pager (the mmu). Hence kept in pager sections.
 */
DECLARE_KEEP_PAGER(stack_tmp_stride);

static unsigned int thread_global_lock __nex_bss = SPINLOCK_UNLOCK;

void thread_init_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	size_t n;
#define INIT_CANARY(name)						\
	for (n = 0; n < ARRAY_SIZE(name); n++) {			\
		uint32_t *start_canary = &GET_START_CANARY(name, n);	\
		uint32_t *end_canary = &GET_END_CANARY(name, n);	\
									\
		*start_canary = start_canary_value;			\
		*end_canary = end_canary_value;				\
	}

	INIT_CANARY(stack_tmp);
	INIT_CANARY(stack_abt);
#if !defined(CFG_WITH_PAGER) && !defined(CFG_NS_VIRTUALIZATION)
	INIT_CANARY(stack_thread);
#endif
#endif/*CFG_WITH_STACK_CANARIES*/
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

#define CANARY_DIED(stack, loc, n, addr) \
	do { \
		EMSG_RAW("Dead canary at %s of '%s[%zu]' (%p)", #loc, #stack, \
			 n, (void *)addr); \
		panic(); \
	} while (0)

void thread_check_canaries(void)
{
#ifdef CFG_WITH_STACK_CANARIES
	uint32_t *canary = NULL;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(stack_tmp); n++) {
		canary = &GET_START_CANARY(stack_tmp, n);
		if (*canary != start_canary_value)
			CANARY_DIED(stack_tmp, start, n, canary);
		canary = &GET_END_CANARY(stack_tmp, n);
		if (*canary != end_canary_value)
			CANARY_DIED(stack_tmp, end, n, canary);
	}

	for (n = 0; n < ARRAY_SIZE(stack_abt); n++) {
		canary = &GET_START_CANARY(stack_abt, n);
		if (*canary != start_canary_value)
			CANARY_DIED(stack_abt, start, n, canary);
		canary = &GET_END_CANARY(stack_abt, n);
		if (*canary != end_canary_value)
			CANARY_DIED(stack_abt, end, n, canary);
	}
#if !defined(CFG_WITH_PAGER) && !defined(CFG_NS_VIRTUALIZATION)
	for (n = 0; n < ARRAY_SIZE(stack_thread); n++) {
		canary = &GET_START_CANARY(stack_thread, n);
		if (*canary != start_canary_value)
			CANARY_DIED(stack_thread, start, n, canary);
		canary = &GET_END_CANARY(stack_thread, n);
		if (*canary != end_canary_value)
			CANARY_DIED(stack_thread, end, n, canary);
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

static struct thread_core_local * __nostackcheck
get_core_local(unsigned int pos)
{
	/*
	 * Foreign interrupts must be disabled before playing with core_local
	 * since we otherwise may be rescheduled to a different core in the
	 * middle of this function.
	 */
	assert(thread_get_exceptions() & THREAD_EXCP_FOREIGN_INTR);

	assert(pos < CFG_TEE_CORE_NB_CORE);
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

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		start = GET_STACK_TOP_SOFT(stack_tmp, n);
		end = GET_STACK_BOTTOM(stack_tmp, n);
		DMSG("tmp [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);
	}
	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		start = GET_STACK_TOP_SOFT(stack_abt, n);
		end = GET_STACK_BOTTOM(stack_abt, n);
		DMSG("abt [%zu] 0x%" PRIxVA "..0x%" PRIxVA, n, start, end);
	}
	for (n = 0; n < CFG_NUM_THREADS; n++) {
		end = threads[n].stack_va_end;
		start = end - STACK_THREAD_SIZE + STACK_CHECK_EXTRA;
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

	thread_init_threads();

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
	return thr->stack_va_end - STACK_THREAD_SIZE;
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
	bool ret = false;

	if (l->flags & THREAD_CLF_TMP) {
		if (hard)
			*start = GET_STACK_TOP_HARD(stack_tmp, pos);
		else
			*start = GET_STACK_TOP_SOFT(stack_tmp, pos);
		*end = GET_STACK_BOTTOM(stack_tmp, pos);
		ret = true;
	} else if (l->flags & THREAD_CLF_ABORT) {
		if (hard)
			*start = GET_STACK_TOP_HARD(stack_abt, pos);
		else
			*start = GET_STACK_TOP_SOFT(stack_abt, pos);
		*end = GET_STACK_BOTTOM(stack_abt, pos);
		ret = true;
	} else if (!l->flags) {
		if (ct < 0 || ct >= CFG_NUM_THREADS)
			goto out;

		*end = threads[ct].stack_va_end;
		*start = *end - STACK_THREAD_SIZE;
		if (!hard)
			*start += STACK_CHECK_EXTRA;
		ret = true;
	}
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
bool __weak thread_is_in_normal_mode(void)
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

		/* Add the region to the pager */
		tee_pager_add_core_region(tee_mm_get_smem(mm) + SMALL_PAGE_SIZE,
					  PAGED_REGION_TYPE_LOCK, fobj);
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
		if (!thread_init_stack(n, GET_STACK_BOTTOM(stack_thread, n)))
			panic("thread_init_stack failed");
	}
}
#endif /*CFG_WITH_PAGER*/

void thread_init_threads(void)
{
	size_t n = 0;

	init_thread_stacks();
	print_stack_limits();
	pgt_init();

	mutex_lockdep_init();

	for (n = 0; n < CFG_NUM_THREADS; n++)
		TAILQ_INIT(&threads[n].tsd.sess_stack);
}

void __nostackcheck thread_init_thread_core_local(void)
{
	size_t n = 0;
	struct thread_core_local *tcl = thread_core_local;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		tcl[n].curr_thread = THREAD_ID_INVALID;
		tcl[n].flags = THREAD_CLF_TMP;
	}
	tcl[0].tmp_stack_va_end = GET_STACK_BOTTOM(stack_tmp, 0);
}

void __nostackcheck thread_init_core_local_stacks(void)
{
	size_t n = 0;
	struct thread_core_local *tcl = thread_core_local;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++) {
		tcl[n].tmp_stack_va_end = GET_STACK_BOTTOM(stack_tmp, n) -
					  STACK_TMP_OFFS;
		tcl[n].abt_stack_va_end = GET_STACK_BOTTOM(stack_abt, n);
	}
}

#if defined(CFG_CORE_PAUTH)
void thread_init_thread_pauth_keys(void)
{
	size_t n = 0;

	for (n = 0; n < CFG_NUM_THREADS; n++)
		if (crypto_rng_read(&threads[n].keys, sizeof(threads[n].keys)))
			panic("Failed to init thread pauth keys");
}

void thread_init_core_local_pauth_keys(void)
{
	struct thread_core_local *tcl = thread_core_local;
	size_t n = 0;

	for (n = 0; n < CFG_TEE_CORE_NB_CORE; n++)
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
