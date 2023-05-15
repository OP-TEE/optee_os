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
bool ffa_mem_reclaim(struct thread_smc_args *args,
		     struct sp_session *caller_sp);

#ifdef CFG_SECURE_PARTITION
void spmc_sp_start_thread(struct thread_smc_args *args);
int spmc_sp_add_share(struct ffa_rxtx *rxtx,
		      size_t blen, uint64_t *global_handle,
		      struct sp_session *owner_sp);
#else
static inline void spmc_sp_start_thread(struct thread_smc_args *args __unused)
{
}

static inline int spmc_sp_add_share(struct ffa_rxtx *rxtx __unused,
				    size_t blen __unused,
				    uint64_t *global_handle __unused,
				    struct sp_session *owner_sp __unused)
{
	return FFA_NOT_SUPPORTED;
}
#endif

#endif /* __KERNEL_SPMC_SP_HANDLER_H */
