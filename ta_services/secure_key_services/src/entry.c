// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2018, Linaro Limited
 */

#include <compiler.h>
#include <sks_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

TEE_Result TA_CreateEntryPoint(void)
{
	// TODO: initialize the token

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **session)
{
	// TODO: get a identifier for the client session
	*session = NULL;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session __unused)
{
	// TODO: release identifier of the client session
}

/*
 * Entry point for SKS TA commands
 *
 * ABI: param#0 is control buffer with serialazed arguments.
 *	param#1 is the input data buffer
 *	param#2 is the output data buffer (also used to return handles)
 *	param#3 is not used
 *
 * Param#0 ctrl, if defined is an in/out buffer, is used to send back to
 * the client a Cryptoki status ID that superseeds the TEE result code which
 * will be force to TEE_SUCCESS. Note that some Cryptoki error status are
 * sent straight through TEE result code. See sks2tee_noerr().
 */
TEE_Result TA_InvokeCommandEntryPoint(void *session __unused, uint32_t cmd,
				      uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Param *ctrl __maybe_unused = NULL;
	TEE_Param *in __maybe_unused = NULL;
	TEE_Param *out __maybe_unused = NULL;
	TEE_Result res;

	if (TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INOUT)
		ctrl = &params[0];
	else if (TEE_PARAM_TYPE_GET(ptypes, 0) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT)
		in = &params[1];
	else if (TEE_PARAM_TYPE_GET(ptypes, 1) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT)
		out = &params[2];
	else if (TEE_PARAM_TYPE_GET(ptypes, 2) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	if (TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
		goto bad_types;

	DMSG("%s ctrl %" PRIu32 "@%p, in %" PRIu32 "@%p, out %" PRIu32 "@%p",
		sks2str_skscmd(cmd),
		ctrl ? ctrl->memref.size : 0, ctrl ? ctrl->memref.buffer : 0,
		in ? in->memref.size : 0, in ? in->memref.buffer : 0,
		out ? out->memref.size : 0, out ? out->memref.buffer : 0);

	switch (cmd) {
	case SKS_CMD_PING:
		res = TEE_SUCCESS;
		break;

	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return res;

bad_types:
	DMSG("Bad parameter types used at SKS TA entry:");
	DMSG("- parameter #0: formated input request buffer or none");
	DMSG("- parameter #1: processed input data buffer or none");
	DMSG("- parameter #2: processed output data buffer or none");
	DMSG("- parameter #3: none");
	return TEE_ERROR_BAD_PARAMETERS;
}
