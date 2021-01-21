/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Arm Limited.
 */
#ifndef __KERNEL_SPMC_SP_HANDLER_H
#define __KERNEL_SPMC_SP_HANDLER_H

#include <assert.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/secure_partition.h>
#include <tee_api_types.h>
#include <tee/entry_std.h>

#define FFA_DST(x)                             ((x) & 0xffff)
#define FFA_SRC(x)                             (((x) >> 16) & 0xffff)

void spmc_sp_thread_entry(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);
void spmc_sp_start_thread(struct thread_smc_args *args);
void spmc_sp_msg_handler(struct thread_smc_args *args,
			 struct sp_session *caller_sp);
#endif /* __KERNEL_SPMC_SP_HANDLER_H */
