/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_STMM_SP_H
#define __KERNEL_STMM_SP_H

#include <assert.h>
#include <config.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/user_mode_ctx_struct.h>
#include <types_ext.h>

struct stmm_ctx {
	struct user_mode_ctx uctx;
	struct tee_ta_ctx ta_ctx;
};

static inline bool is_stmm_ctx(struct ts_ctx *ctx __unused)
{
	return false;
}

static inline struct stmm_ctx *to_stmm_ctx(struct ts_ctx *ctx __unused)
{
	assert(is_stmm_ctx(ctx));
	return NULL;
}

static inline TEE_Result
stmm_init_session(const TEE_UUID *uuid __unused,
		  struct tee_ta_session *s __unused)
{
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static inline const TEE_UUID *stmm_get_uuid(void) { return NULL; }

#endif /*__KERNEL_STMM_SP_H*/
