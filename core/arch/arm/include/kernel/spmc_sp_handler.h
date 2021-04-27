/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Arm Limited.
 */
#ifndef __KERNEL_SPMC_SP_HANDLER_H
#define __KERNEL_SPMC_SP_HANDLER_H

#include <assert.h>
#include <kernel/secure_partition.h>
#include <kernel/user_mode_ctx_struct.h>
#include <tee_api_types.h>
#include <tee/entry_std.h>

#define FFA_DST(x)	((x) & UINT16_MAX)
#define FFA_SRC(x)	(((x) >> 16) & UINT16_MAX)

void spmc_sp_thread_entry(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);
void spmc_sp_msg_handler(struct thread_smc_args *args,
			 struct sp_session *caller_sp);
TEE_Result spmc_sp_add_share(struct ffa_mem_transaction *input_descr,
			     uint64_t global_handle, size_t blen);

struct sp_shared_mem {
	size_t counter;
	struct shared_mem *s_mem;
	struct ffa_mem_access *access_descr;
	uint16_t endpoint_id;
	SLIST_ENTRY(sp_shared_mem) link;
	bool zero_flag;
};

struct shared_mem {
	TAILQ_ENTRY(shared_mem) link;
	uint16_t owner_id;
	struct ffa_mem_transaction *mem_descr;
	SLIST_HEAD(mem_head_t, sp_shared_mem) sp_head;
};

#ifdef CFG_SECURE_PARTITION
void spmc_sp_start_thread(struct thread_smc_args *args);
#else
static inline void spmc_sp_start_thread(struct thread_smc_args *args __unused)
{
}
#endif
#endif /* __KERNEL_SPMC_SP_HANDLER_H */
