/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __KERNEL_USER_MODE_CTX_H
#define __KERNEL_USER_MODE_CTX_H

#include <assert.h>
#include <kernel/user_mode_ctx_struct.h>
#include <kernel/user_ta.h>
#include <stdbool.h>

static inline bool is_user_mode_ctx(struct tee_ta_ctx *ctx)
{
	return is_user_ta_ctx(ctx);
}

static inline struct user_mode_ctx *to_user_mode_ctx(struct tee_ta_ctx *ctx)
{
	assert(is_user_mode_ctx(ctx));
	return container_of(ctx, struct user_mode_ctx, ctx);
}

void user_mode_ctx_print_mappings(struct user_mode_ctx *umctx);

#endif /*__KERNEL_USER_MODE_CTX_H*/
