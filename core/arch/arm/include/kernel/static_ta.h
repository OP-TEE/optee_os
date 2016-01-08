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
#ifndef KERNEL_STATIC_TA_H
#define KERNEL_STATIC_TA_H

#include <compiler.h>
#include <kernel/tee_ta_manager.h>
#include <tee_api_types.h>
#include <util.h>
#include <assert.h>

struct static_ta_head {
	TEE_UUID uuid;
	const char *name;

	TEE_Result (*create_entry_point)(void);
	void (*destroy_entry_point)(void);
	TEE_Result (*open_session_entry_point)(uint32_t nParamTypes,
			TEE_Param pParams[4], void **ppSessionContext);
	void (*close_session_entry_point)(void *pSessionContext);
	TEE_Result (*invoke_command_entry_point)(void *pSessionContext,
			uint32_t nCommandID, uint32_t nParamTypes,
			TEE_Param pParams[4]);
};

#define static_ta_register(...) static const struct static_ta_head __head \
			__used __section("ta_head_section") = { __VA_ARGS__ }


struct static_ta_ctx {
	const struct static_ta_head *static_ta;
	struct tee_ta_ctx ctx;
};

static inline bool is_static_ta_ctx(struct tee_ta_ctx *ctx)
{
	return !(ctx->flags & TA_FLAG_USER_MODE);
}

static inline struct static_ta_ctx *to_static_ta_ctx(struct tee_ta_ctx *ctx)
{
	assert(is_static_ta_ctx(ctx));
	return container_of(ctx, struct static_ta_ctx, ctx);
}

TEE_Result tee_ta_init_static_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s);

#endif /*KERNEL_STATIC_TA_H*/

