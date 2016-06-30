/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <types_ext.h>
#include <stdlib.h>
#include <mm/core_memprot.h>
#include <sm/tee_mon.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/static_ta.h>
#include <trace.h>

/* Maps static TA params */
static TEE_Result tee_ta_param_pa2va(struct tee_ta_param *param)
{
	size_t n;
	void *va;
	paddr_t pa;

	/*
	 * If a static TA is called from another TA the mapping
	 * of that TA is borrowed and the addresses are already
	 * virtual.
	 */
	if (tee_ta_get_calling_session())
		return TEE_SUCCESS;

	for (n = 0; n < 4; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			pa = (paddr_t)param->params[n].memref.buffer;
			va = phys_to_virt(pa, MEM_AREA_NSEC_SHM);
			if (!va)
				return TEE_ERROR_BAD_PARAMETERS;
			param->params[n].memref.buffer = va;
			break;

		default:
			continue;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result static_ta_enter_open_session(struct tee_ta_session *s,
			struct tee_ta_param *param, TEE_ErrorOrigin *eo)
{
	TEE_Result res;
	struct static_ta_ctx *stc = to_static_ta_ctx(s->ctx);

	tee_ta_push_current_session(s);
	res = tee_ta_param_pa2va(param);
	if (res != TEE_SUCCESS) {
		*eo = TEE_ORIGIN_TEE;
		goto out;
	}

	*eo = TEE_ORIGIN_TRUSTED_APP;
	if (s->ctx->ref_count == 1) {
		res = stc->static_ta->create_entry_point();
		if (res != TEE_SUCCESS)
			goto out;
	}
	res = stc->static_ta->open_session_entry_point(param->types,
					param->params, &s->user_ctx);

out:
	tee_ta_pop_current_session();
	return res;
}

static TEE_Result static_ta_enter_invoke_cmd(struct tee_ta_session *s,
			uint32_t cmd, struct tee_ta_param *param,
			TEE_ErrorOrigin *eo)
{
	TEE_Result res;
	struct static_ta_ctx *stc = to_static_ta_ctx(s->ctx);

	tee_ta_push_current_session(s);
	res = tee_ta_param_pa2va(param);
	if (res != TEE_SUCCESS) {
		*eo = TEE_ORIGIN_TEE;
		goto out;
	}

	*eo = TEE_ORIGIN_TRUSTED_APP;
	res = stc->static_ta->invoke_command_entry_point(s->user_ctx, cmd,
					param->types, param->params);
out:
	tee_ta_pop_current_session();
	return res;
}

static void static_ta_enter_close_session(struct tee_ta_session *s)
{
	struct static_ta_ctx *stc = to_static_ta_ctx(s->ctx);

	tee_ta_push_current_session(s);
	stc->static_ta->close_session_entry_point(s->user_ctx);
	if (s->ctx->ref_count == 1)
		stc->static_ta->destroy_entry_point();
	tee_ta_pop_current_session();
}

static void static_ta_destroy(struct tee_ta_ctx *ctx __unused)
{
	/* Nothing to do */
}

static const struct tee_ta_ops static_ta_ops = {
	.enter_open_session = static_ta_enter_open_session,
	.enter_invoke_cmd = static_ta_enter_invoke_cmd,
	.enter_close_session = static_ta_enter_close_session,
	.destroy = static_ta_destroy,
};


/* Defined in link script */
extern const struct static_ta_head __start_ta_head_section;
extern const struct static_ta_head __stop_ta_head_section;

/*-----------------------------------------------------------------------------
 * Initialises a session based on the UUID or ptr to the ta
 * Returns ptr to the session (ta_session) and a TEE_Result
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_init_static_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s)
{
	struct static_ta_ctx *stc = NULL;
	struct tee_ta_ctx *ctx;
	const struct static_ta_head *ta;

	DMSG("   Lookup for Static TA %pUl", (void *)uuid);

	ta = &__start_ta_head_section;
	while (true) {
		if (ta >= &__stop_ta_head_section)
			return TEE_ERROR_ITEM_NOT_FOUND;
		if (memcmp(&ta->uuid, uuid, sizeof(TEE_UUID)) == 0)
			break;
		ta++;
	}

	/* Load a new TA and create a session */
	DMSG("      Open %s", ta->name);
	stc = calloc(1, sizeof(struct static_ta_ctx));
	if (!stc)
		return TEE_ERROR_OUT_OF_MEMORY;
	ctx = &stc->ctx;

	ctx->ref_count = 1;
	s->ctx = ctx;
	ctx->flags = TA_FLAG_MULTI_SESSION;
	stc->static_ta = ta;
	ctx->uuid = ta->uuid;
	ctx->ops = &static_ta_ops;
	TAILQ_INSERT_TAIL(&tee_ctxes, ctx, link);

	DMSG("      %s : %pUl", stc->static_ta->name, (void *)&ctx->uuid);

	return TEE_SUCCESS;
}
