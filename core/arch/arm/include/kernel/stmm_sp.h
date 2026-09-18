/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2020, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */

#ifndef __KERNEL_STMM_SP_H
#define __KERNEL_STMM_SP_H

#include <assert.h>
#include <config.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/user_mode_ctx_struct.h>
#include <types_ext.h>
#include <util.h>

struct stmm_ctx {
	struct user_mode_ctx uctx;
	struct tee_ta_ctx ta_ctx;
	struct thread_ctx_regs regs;
	vaddr_t ns_comm_buf_addr;
	unsigned int ns_comm_buf_size;
};

extern const struct ts_ops stmm_sp_ops;

static inline bool is_stmm_ctx(struct ts_ctx *ctx __maybe_unused)
{
	return IS_ENABLED(CFG_WITH_STMM_SP) && ctx && ctx->ops == &stmm_sp_ops;
}

static inline struct stmm_ctx *to_stmm_ctx(struct ts_ctx *ctx)
{
	assert(is_stmm_ctx(ctx));
	return container_of(ctx, struct stmm_ctx, ta_ctx.ts_ctx);
}

#ifdef CFG_WITH_STMM_SP
/*
 * Setup session context for the StMM application
 * @uuid: TA UUID
 * @sess: Session for which to setup the StMM context
 *
 * This function must be called with tee_ta_mutex locked.
 */
TEE_Result stmm_init_session(const TEE_UUID *uuid,
			     struct tee_ta_session *s);

/*
 * Finalize session context initialization the StMM application
 * @sess: Session for which to finalize StMM context
 */
TEE_Result stmm_complete_session(struct tee_ta_session *s);
#else
static inline TEE_Result
stmm_init_session(const TEE_UUID *uuid __unused,
		  struct tee_ta_session *s __unused)
{
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static inline TEE_Result
stmm_complete_session(struct tee_ta_session *s __unused)
{
	return TEE_ERROR_GENERIC;
}
#endif

#ifdef CFG_WITH_STMM_SP
const TEE_UUID *stmm_get_uuid(void);
#else
static inline const TEE_UUID *stmm_get_uuid(void) { return NULL; }
#endif

#endif /*__KERNEL_STMM_SP_H*/
