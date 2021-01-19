/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2021, Arm Limited
 */

#ifndef __KERNEL_USER_MODE_CTX_H
#define __KERNEL_USER_MODE_CTX_H

#include <assert.h>
#include <kernel/secure_partition.h>
#include <kernel/stmm_sp.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/user_ta.h>
#include <stdbool.h>

static inline bool is_user_mode_ctx(struct ts_ctx *ctx)
{
	return is_user_ta_ctx(ctx) || is_stmm_ctx(ctx) || is_sp_ctx(ctx);
}

static inline struct user_mode_ctx *to_user_mode_ctx(struct ts_ctx *ctx)
{
	if (is_user_ta_ctx(ctx))
		return &to_user_ta_ctx(ctx)->uctx;
	else if (is_sp_ctx(ctx))
		return &to_sp_ctx(ctx)->uctx;
	else
		return &to_stmm_ctx(ctx)->uctx;
}

void user_mode_ctx_print_mappings(struct user_mode_ctx *umctx);

#endif /*__KERNEL_USER_MODE_CTX_H*/
