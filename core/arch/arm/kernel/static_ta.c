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
#include <mm/core_mmu.h>
#include <sm/tee_mon.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/static_ta.h>
#include <trace.h>

typedef enum {
	COMMAND_INVOKE_COMMAND = 0,
	COMMAND_OPEN_SESSION,
	COMMAND_CREATE_ENTRY_POINT,
	COMMAND_CLOSE_SESSION,
	COMMAND_DESTROY_ENTRY_POINT,
} command_t;

struct param_ta {
	struct tee_ta_session *sess;
	struct static_ta_ctx *stc;
	uint32_t cmd;
	struct tee_ta_param *param;
	TEE_Result res;
};

/*
 * Jumpers for the static TAs.
 */
static void jumper_invokecommand(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->stc->static_ta->invoke_command_entry_point(
			(void *)args->sess->user_ctx,
			(uint32_t)args->cmd,
			(uint32_t)args->param->types,
			(TEE_Param *)args->param->params);
	OUTMSG("%x", args->res);
}

static void jumper_opensession(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->stc->static_ta->open_session_entry_point(
			(uint32_t)args->param->types,
			(TEE_Param *)args->param->params,
			(void **)&args->sess->user_ctx);
	OUTMSG("%x", args->res);
}

static void jumper_createentrypoint(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->res = args->stc->static_ta->create_entry_point();
	OUTMSG("%x", args->res);
}

static void jumper_closesession(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->stc->static_ta->close_session_entry_point(
			(void *)args->sess->user_ctx);
	args->res = TEE_SUCCESS;
	OUTMSG("%x", args->res);
}

static void jumper_destroyentrypoint(void *voidargs)
{
	struct param_ta *args = (struct param_ta *)voidargs;

	INMSG("");
	args->stc->static_ta->destroy_entry_point();
	args->res = TEE_SUCCESS;
	OUTMSG("%x", args->res);
}

/* Stack size is updated to take into account */
/* the size of the needs of the tee internal libs */

static TEE_Result invoke_ta(struct tee_ta_session *sess, uint32_t cmd,
			    struct tee_ta_param *param, command_t commandtype)
{
	struct param_ta ptas;

	ptas.sess = sess;
	ptas.stc = to_static_ta_ctx(sess->ctx);
	ptas.cmd = cmd;
	ptas.param = param;
	ptas.res = TEE_ERROR_TARGET_DEAD;

	switch (commandtype) {
	case COMMAND_INVOKE_COMMAND:
		jumper_invokecommand(&ptas);
		break;
	case COMMAND_OPEN_SESSION:
		jumper_opensession(&ptas);
		break;
	case COMMAND_CREATE_ENTRY_POINT:
		jumper_createentrypoint(&ptas);
		break;
	case COMMAND_CLOSE_SESSION:
		jumper_closesession(&ptas);
		break;
	case COMMAND_DESTROY_ENTRY_POINT:
		jumper_destroyentrypoint(&ptas);
		break;
	default:
		EMSG("Do not know how to run the command %d", commandtype);
		ptas.res = TEE_ERROR_GENERIC;
		break;
	}

	OUTRMSG(ptas.res);
	return ptas.res;
}

/* Maps kernal TA params */
static TEE_Result tee_ta_param_pa2va(struct tee_ta_session *sess,
				     struct tee_ta_param *param)
{
	size_t n;
	void *va;

	/*
	 * If kernel TA is called from another TA the mapping
	 * of that TA is borrowed and the addresses are already
	 * virtual.
	 */
	if (sess != NULL && sess->calling_sess != NULL)
		return TEE_SUCCESS;

	for (n = 0; n < 4; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			if (core_pa2va((paddr_t)param->params[n].memref.buffer,
				       &va))
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

	tee_ta_set_current_session(s);
	res = tee_ta_param_pa2va(s, param);
	if (res != TEE_SUCCESS) {
		*eo = TEE_ORIGIN_TEE;
		return res;
	}

	*eo = TEE_ORIGIN_TRUSTED_APP;
	if (s->ctx->ref_count == 1) {
		res = invoke_ta(s, 0, 0, COMMAND_CREATE_ENTRY_POINT);
		if (res != TEE_SUCCESS)
			return res;
	}
	res = invoke_ta(s, 0, param, COMMAND_OPEN_SESSION);
	tee_ta_set_current_session(NULL);
	return res;
}

static TEE_Result static_ta_enter_invoke_cmd(struct tee_ta_session *s,
			uint32_t cmd, struct tee_ta_param *param,
			TEE_ErrorOrigin *eo)
{
	TEE_Result res;

	tee_ta_set_current_session(s);
	res = tee_ta_param_pa2va(s, param);
	if (res != TEE_SUCCESS) {
		*eo = TEE_ORIGIN_TEE;
		return res;
	}

	*eo = TEE_ORIGIN_TRUSTED_APP;
	res = invoke_ta(s, cmd, param, COMMAND_INVOKE_COMMAND);
	tee_ta_set_current_session(NULL);
	return res;
}

static void static_ta_enter_close_session(struct tee_ta_session *s)
{
	tee_ta_set_current_session(s);
	invoke_ta(s, 0, 0, COMMAND_CLOSE_SESSION);
	if (s->ctx->ref_count == 1)
		invoke_ta(s, 0, 0, COMMAND_DESTROY_ENTRY_POINT);
	tee_ta_set_current_session(NULL);
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


/*-----------------------------------------------------------------------------
 * Initialises a session based on the UUID or ptr to the ta
 * Returns ptr to the session (ta_session) and a TEE_Result
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_init_static_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s)
{
	struct static_ta_ctx *stc = NULL;
	struct tee_ta_ctx *ctx;
	ta_static_head_t *ta = NULL;

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
