/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef KERNEL_PSEUDO_TA_H
#define KERNEL_PSEUDO_TA_H

#include <assert.h>
#include <compiler.h>
#include <kernel/tee_ta_manager.h>
#include <tee_api_types.h>
#include <user_ta_header.h>
#include <util.h>

#define PTA_MANDATORY_FLAGS	(TA_FLAG_SINGLE_INSTANCE | \
				TA_FLAG_MULTI_SESSION | \
				TA_FLAG_INSTANCE_KEEP_ALIVE)

#define PTA_ALLOWED_FLAGS	(PTA_MANDATORY_FLAGS | \
				TA_FLAG_SECURE_DATA_PATH)

#define PTA_DEFAULT_FLAGS	PTA_MANDATORY_FLAGS

struct pseudo_ta_head {
	TEE_UUID uuid;
	const char *name;
	uint32_t flags;

	TEE_Result (*create_entry_point)(void);
	void (*destroy_entry_point)(void);
	TEE_Result (*open_session_entry_point)(uint32_t nParamTypes,
			TEE_Param pParams[TEE_NUM_PARAMS],
			void **ppSessionContext);
	void (*close_session_entry_point)(void *pSessionContext);
	TEE_Result (*invoke_command_entry_point)(void *pSessionContext,
			uint32_t nCommandID, uint32_t nParamTypes,
			TEE_Param pParams[TEE_NUM_PARAMS]);
};

#define pseudo_ta_register(...) static const struct pseudo_ta_head __head \
			__used __section("ta_head_section") = { __VA_ARGS__ }


struct pseudo_ta_ctx {
	const struct pseudo_ta_head *pseudo_ta;
	struct tee_ta_ctx ctx;
};

static inline bool is_pseudo_ta_ctx(struct tee_ta_ctx *ctx)
{
	return !(ctx->flags & TA_FLAG_USER_MODE);
}

static inline struct pseudo_ta_ctx *to_pseudo_ta_ctx(struct tee_ta_ctx *ctx)
{
	assert(is_pseudo_ta_ctx(ctx));
	return container_of(ctx, struct pseudo_ta_ctx, ctx);
}

TEE_Result tee_ta_init_pseudo_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s);

#endif /* KERNEL_PSEUDO_TA_H */

