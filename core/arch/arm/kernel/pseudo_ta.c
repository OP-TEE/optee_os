// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
 */
#include <initcall.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <sm/tee_mon.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>

#ifdef CFG_SECURE_DATA_PATH
static bool client_is_secure(struct tee_ta_session *s)
{
	/* rely on core entry to have constrained client IDs */
	if (s->clnt_id.login == TEE_LOGIN_TRUSTED_APP)
		return true;

	return false;
}

static bool validate_in_param(struct tee_ta_session *s, struct mobj *mobj)
{
	/* Supplying NULL to query buffer size is OK */
	if (!mobj)
		return true;

	/* for secure clients, core entry always holds valid memref objects */
	if (client_is_secure(s))
		return true;

	/* all non-secure memory references are handled by PTAs */
	if (mobj_is_nonsec(mobj))
		return true;

	return false;
}
#else
static bool validate_in_param(struct tee_ta_session *s __unused,
				struct mobj *mobj __unused)
{
	/* At this point, core has filled only valid accessible memref mobj */
	return true;
}
#endif

/* Maps pseudo TA params */
static TEE_Result copy_in_param(struct tee_ta_session *s __maybe_unused,
				struct tee_ta_param *param,
				TEE_Param tee_param[TEE_NUM_PARAMS],
				bool did_map[TEE_NUM_PARAMS])
{
	size_t n;
	void *va;
	struct param_mem *mem;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			tee_param[n].value.a = param->u[n].val.a;
			tee_param[n].value.b = param->u[n].val.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			mem = &param->u[n].mem;
			if (!validate_in_param(s, mem->mobj))
				return TEE_ERROR_BAD_PARAMETERS;
			va = mobj_get_va(mem->mobj, mem->offs);
			if (!va && mem->size) {
				TEE_Result res;

				res = mobj_inc_map(mem->mobj);
				if (res)
					return res;
				did_map[n] = true;
				va = mobj_get_va(mem->mobj, mem->offs);
				if (!va)
					return TEE_ERROR_BAD_PARAMETERS;
				if (mem->size &&
				    !mobj_get_va(mem->mobj,
						 mem->offs + mem->size - 1))
					return TEE_ERROR_BAD_PARAMETERS;
			}

			tee_param[n].memref.buffer = va;
			tee_param[n].memref.size = mem->size;
			break;
		default:
			memset(tee_param + n, 0, sizeof(TEE_Param));
			break;
		}
	}

	return TEE_SUCCESS;
}

static void update_out_param(TEE_Param tee_param[TEE_NUM_PARAMS],
			     struct tee_ta_param *param)
{
	size_t n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(param->types, n)) {
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			param->u[n].val.a = tee_param[n].value.a;
			param->u[n].val.b = tee_param[n].value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			param->u[n].mem.size = tee_param[n].memref.size;
			break;
		default:
			break;
		}
	}
}

static void unmap_mapped_param(struct tee_ta_param *param,
			       bool did_map[TEE_NUM_PARAMS])
{
	size_t n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		if (did_map[n]) {
			TEE_Result res __maybe_unused;

			res = mobj_dec_map(param->u[n].mem.mobj);
			assert(!res);
		}
	}
}

static TEE_Result pseudo_ta_enter_open_session(struct tee_ta_session *s,
			struct tee_ta_param *param, TEE_ErrorOrigin *eo)
{
	TEE_Result res = TEE_SUCCESS;
	struct pseudo_ta_ctx *stc = to_pseudo_ta_ctx(s->ctx);
	TEE_Param tee_param[TEE_NUM_PARAMS];
	bool did_map[TEE_NUM_PARAMS] = { false };

	tee_ta_push_current_session(s);
	*eo = TEE_ORIGIN_TRUSTED_APP;

	if ((s->ctx->ref_count == 1) && stc->pseudo_ta->create_entry_point) {
		res = stc->pseudo_ta->create_entry_point();
		if (res != TEE_SUCCESS)
			goto out;
	}

	if (stc->pseudo_ta->open_session_entry_point) {
		res = copy_in_param(s, param, tee_param, did_map);
		if (res != TEE_SUCCESS) {
			unmap_mapped_param(param, did_map);
			*eo = TEE_ORIGIN_TEE;
			goto out;
		}

		res = stc->pseudo_ta->open_session_entry_point(param->types,
								tee_param,
								&s->user_ctx);
		update_out_param(tee_param, param);
		unmap_mapped_param(param, did_map);
	}

out:
	tee_ta_pop_current_session();
	return res;
}

static TEE_Result pseudo_ta_enter_invoke_cmd(struct tee_ta_session *s,
			uint32_t cmd, struct tee_ta_param *param,
			TEE_ErrorOrigin *eo)
{
	TEE_Result res;
	struct pseudo_ta_ctx *stc = to_pseudo_ta_ctx(s->ctx);
	TEE_Param tee_param[TEE_NUM_PARAMS];
	bool did_map[TEE_NUM_PARAMS] = { false };

	tee_ta_push_current_session(s);
	res = copy_in_param(s, param, tee_param, did_map);
	if (res != TEE_SUCCESS) {
		unmap_mapped_param(param, did_map);
		*eo = TEE_ORIGIN_TEE;
		goto out;
	}

	*eo = TEE_ORIGIN_TRUSTED_APP;
	res = stc->pseudo_ta->invoke_command_entry_point(s->user_ctx, cmd,
							 param->types,
							 tee_param);
	update_out_param(tee_param, param);
	unmap_mapped_param(param, did_map);
out:
	tee_ta_pop_current_session();
	return res;
}

static void pseudo_ta_enter_close_session(struct tee_ta_session *s)
{
	struct pseudo_ta_ctx *stc = to_pseudo_ta_ctx(s->ctx);

	tee_ta_push_current_session(s);

	if (stc->pseudo_ta->close_session_entry_point)
		stc->pseudo_ta->close_session_entry_point(s->user_ctx);

	if ((s->ctx->ref_count == 1) && stc->pseudo_ta->destroy_entry_point)
		stc->pseudo_ta->destroy_entry_point();

	tee_ta_pop_current_session();
}

static void pseudo_ta_destroy(struct tee_ta_ctx *ctx)
{
	free(to_pseudo_ta_ctx(ctx));
}

static const struct tee_ta_ops pseudo_ta_ops = {
	.enter_open_session = pseudo_ta_enter_open_session,
	.enter_invoke_cmd = pseudo_ta_enter_invoke_cmd,
	.enter_close_session = pseudo_ta_enter_close_session,
	.destroy = pseudo_ta_destroy,
};

bool is_pseudo_ta_ctx(struct tee_ta_ctx *ctx)
{
	return ctx->ops == &pseudo_ta_ops;
}

/* Insures declared pseudo TAs conforms with core expectations */
static TEE_Result verify_pseudo_tas_conformance(void)
{
	const struct pseudo_ta_head *start =
		SCATTERED_ARRAY_BEGIN(pseudo_tas, struct pseudo_ta_head);
	const struct pseudo_ta_head *end =
		SCATTERED_ARRAY_END(pseudo_tas, struct pseudo_ta_head);
	const struct pseudo_ta_head *pta;

	for (pta = start; pta < end; pta++) {
		const struct pseudo_ta_head *pta2;

		/* PTAs must all have a specific UUID */
		for (pta2 = pta + 1; pta2 < end; pta2++) {
			if (!memcmp(&pta->uuid, &pta2->uuid, sizeof(TEE_UUID)))
				goto err;
		}

		if (!pta->name ||
		    (pta->flags & PTA_MANDATORY_FLAGS) != PTA_MANDATORY_FLAGS ||
		    pta->flags & ~PTA_ALLOWED_FLAGS ||
		    !pta->invoke_command_entry_point)
			goto err;
	}
	return TEE_SUCCESS;
err:
	DMSG("pseudo TA error at %p", (void *)pta);
	panic("PTA");
}

service_init(verify_pseudo_tas_conformance);

/*-----------------------------------------------------------------------------
 * Initialises a session based on the UUID or ptr to the ta
 * Returns ptr to the session (ta_session) and a TEE_Result
 *---------------------------------------------------------------------------*/
TEE_Result tee_ta_init_pseudo_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s)
{
	struct pseudo_ta_ctx *stc = NULL;
	struct tee_ta_ctx *ctx;
	const struct pseudo_ta_head *ta;

	DMSG("Lookup pseudo TA %pUl", (void *)uuid);

	ta = SCATTERED_ARRAY_BEGIN(pseudo_tas, struct pseudo_ta_head);
	while (true) {
		if (ta >= SCATTERED_ARRAY_END(pseudo_tas,
					      struct pseudo_ta_head))
			return TEE_ERROR_ITEM_NOT_FOUND;
		if (memcmp(&ta->uuid, uuid, sizeof(TEE_UUID)) == 0)
			break;
		ta++;
	}

	/* Load a new TA and create a session */
	DMSG("Open %s", ta->name);
	stc = calloc(1, sizeof(struct pseudo_ta_ctx));
	if (!stc)
		return TEE_ERROR_OUT_OF_MEMORY;
	ctx = &stc->ctx;

	ctx->ref_count = 1;
	s->ctx = ctx;
	ctx->flags = ta->flags;
	stc->pseudo_ta = ta;
	ctx->uuid = ta->uuid;
	ctx->ops = &pseudo_ta_ops;
	TAILQ_INSERT_TAIL(&tee_ctxes, ctx, link);

	DMSG("%s : %pUl", stc->pseudo_ta->name, (void *)&ctx->uuid);

	return TEE_SUCCESS;
}
