/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __KERNEL_THREAD_PRIVATE_H
#define __KERNEL_THREAD_PRIVATE_H

#include <util.h>
#ifndef __ASSEMBLER__

#include <kernel/mutex.h>
#include <kernel/thread.h>
#include <kernel/thread_private_arch.h>
#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>

enum thread_state {
	THREAD_STATE_FREE,
	THREAD_STATE_SUSPENDED,
	THREAD_STATE_ACTIVE,
};

struct thread_shm_cache_entry {
	struct mobj *mobj;
	size_t size;
	enum thread_shm_type type;
	enum thread_shm_cache_user user;
	SLIST_ENTRY(thread_shm_cache_entry) link;
};

SLIST_HEAD(thread_shm_cache, thread_shm_cache_entry);

struct thread_ctx {
	struct thread_ctx_regs regs;
	enum thread_state state;
	vaddr_t stack_va_end;
	uint32_t flags;
	struct core_mmu_user_map user_map;
	bool have_user_map;
#if defined(ARM64) || defined(RV64)
	vaddr_t kern_sp;	/* Saved kernel SP during user TA execution */
#endif
#ifdef CFG_CORE_PAUTH
	struct thread_pauth_keys keys;
#endif
#ifdef CFG_WITH_VFP
	struct thread_vfp_state vfp_state;
#endif
	void *rpc_arg;
	struct mobj *rpc_mobj;
	struct thread_shm_cache shm_cache;
	struct thread_specific_data tsd;
};
#endif /*__ASSEMBLER__*/

/* Describes the flags field of struct thread_core_local */
#define THREAD_CLF_SAVED_SHIFT			4
#define THREAD_CLF_CURR_SHIFT			0
#define THREAD_CLF_MASK				0xf
#define THREAD_CLF_TMP_SHIFT			0
#define THREAD_CLF_ABORT_SHIFT			1
#define THREAD_CLF_IRQ_SHIFT			2
#define THREAD_CLF_FIQ_SHIFT			3

#define THREAD_CLF_TMP				BIT(THREAD_CLF_TMP_SHIFT)
#define THREAD_CLF_ABORT			BIT(THREAD_CLF_ABORT_SHIFT)
#define THREAD_CLF_IRQ				BIT(THREAD_CLF_IRQ_SHIFT)
#define THREAD_CLF_FIQ				BIT(THREAD_CLF_FIQ_SHIFT)

#ifndef __ASSEMBLER__
extern const void *stack_tmp_export;
extern const uint32_t stack_tmp_stride;
extern struct thread_ctx threads[];
extern struct thread_core_local thread_core_local[];

#ifdef CFG_WITH_STACK_CANARIES
#define STACK_CANARY_SIZE	(4 * sizeof(long))
#else
#define STACK_CANARY_SIZE	0
#endif

/* Checks stack canaries */
void thread_check_canaries(void);

void thread_lock_global(void);
void thread_unlock_global(void);

/* Frees the cache of allocated FS RPC memory */
void thread_rpc_shm_cache_clear(struct thread_shm_cache *cache);
#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_PRIVATE_H*/
