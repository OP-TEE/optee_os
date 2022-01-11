// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/mobj.h>
#include <optee_rpc_cmd.h>
#include <pta_gprof.h>
#include <string.h>

static TEE_Result gprof_send_rpc(TEE_UUID *uuid, void *buf, size_t len,
				 uint32_t *id)
{
	struct thread_param params[3] = { };
	struct mobj *mobj;
	TEE_Result res = TEE_ERROR_GENERIC;
	char *va;

	mobj = thread_rpc_alloc_payload(sizeof(*uuid) + len);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;

	va = mobj_get_va(mobj, 0, sizeof(*uuid) + len);
	if (!va)
		goto exit;

	memcpy(va, uuid, sizeof(*uuid));
	memcpy(va + sizeof(*uuid), buf, len);

	params[0] = THREAD_PARAM_VALUE(INOUT, *id, 0, 0);
	params[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, sizeof(*uuid));
	params[2] = THREAD_PARAM_MEMREF(IN, mobj, sizeof(*uuid), len);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_GPROF, 3, params);
	if (res != TEE_SUCCESS)
		goto exit;

	*id = (uint32_t)params[0].u.value.a;
exit:
	thread_rpc_free_payload(mobj);
	return res;
}

static TEE_Result gprof_send(struct ts_session *s, uint32_t param_types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return gprof_send_rpc(&s->ctx->uuid, params[1].memref.buffer,
			      params[1].memref.size, &params[0].value.a);
}

static TEE_Result gprof_start_pc_sampling(struct ts_session *s,
					  uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct sample_buf *sbuf = NULL;
	uint32_t offset = 0;
	uint32_t scale = 0;
	uint32_t len = 0;
	uaddr_t buf = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (s->sbuf) {
		DMSG("PC sampling already started");
		return TEE_ERROR_BAD_STATE;
	}

	buf = (uaddr_t)params[0].memref.buffer;
	len = params[0].memref.size;
	offset = params[1].value.a;
	scale = params[1].value.b;

	sbuf = calloc(1, sizeof(*sbuf));
	if (!sbuf)
		return TEE_ERROR_OUT_OF_MEMORY;

	sbuf->samples = (uint16_t *)buf;
	sbuf->nsamples = len / sizeof(*sbuf->samples);
	sbuf->offset = offset;
	sbuf->scale = scale;
	sbuf->freq = read_cntfrq();
	sbuf->enabled = true;
	s->sbuf = sbuf;

	return TEE_SUCCESS;
}

static TEE_Result gprof_stop_pc_sampling(struct ts_session *s,
					 uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct sample_buf *sbuf = NULL;
	uint32_t rate = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	sbuf = s->sbuf;
	if (!sbuf)
		return TEE_ERROR_BAD_STATE;
	assert(sbuf->samples);

	/* Stop sampling */
	if (sbuf->enabled)
		sbuf->enabled = false;

	rate = ((uint64_t)sbuf->count * sbuf->freq) / sbuf->usr;
	params[0].value.a = rate;

	DMSG("TA sampling stats: sample count=%" PRIu32 " user time=%" PRIu64
	     " cntfrq=%" PRIu32 " rate=%" PRIu32, sbuf->count, sbuf->usr,
	     sbuf->freq, rate);

	free(sbuf);
	s->sbuf = NULL;

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct ts_session *s = ts_get_calling_session();

	/* Check that we're called from a user TA */
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	if (!is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	struct ts_session *s = ts_get_calling_session();

	switch (cmd_id) {
	case PTA_GPROF_SEND:
		return gprof_send(s, param_types, params);
	case PTA_GPROF_START_PC_SAMPLING:
		return gprof_start_pc_sampling(s, param_types, params);
	case PTA_GPROF_STOP_PC_SAMPLING:
		return gprof_stop_pc_sampling(s, param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_GPROF_UUID, .name = "gprof",
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
