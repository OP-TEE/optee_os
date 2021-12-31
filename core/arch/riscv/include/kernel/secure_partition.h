/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_SECURE_PARTITION_H
#define __KERNEL_SECURE_PARTITION_H

#include <assert.h>
#include <kernel/embedded_ts.h>
#include <kernel/user_mode_ctx_struct.h>
#include <stdint.h>

struct sp_ctx {
	struct user_mode_ctx uctx;
	struct ts_ctx ts_ctx;
};

static inline bool is_sp_ctx(struct ts_ctx *ctx __unused)
{
	return false;
}

static inline struct sp_session *__noprof
to_sp_session(struct ts_session *sess __unused)
{
	assert(is_sp_ctx(sess->ctx));
	return NULL;
}

static inline struct sp_ctx *to_sp_ctx(struct ts_ctx *ctx __unused)
{
	assert(is_sp_ctx(ctx));
	return NULL;
}

#endif /* __KERNEL_SECURE_PARTITION_H */
