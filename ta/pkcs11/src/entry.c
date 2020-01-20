// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <compiler.h>
#include <pkcs11_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <util.h>

#include "pkcs11_helpers.h"

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **session)
{
	*session = NULL;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session __unused)
{
}

/*
 * Entry point for invocation command PKCS11_CMD_PING
 *
 * @ctrl - param memref[0] or NULL: expected NULL
 * @in - param memref[1] or NULL: expected NULL
 * @out - param memref[2] or NULL
 *
 * Return a PKCS11_CKR_* value
 */
static uint32_t entry_ping(TEE_Param *ctrl, TEE_Param *in, TEE_Param *out)
{
	const uint32_t ver[] = {
		PKCS11_TA_VERSION_MAJOR,
		PKCS11_TA_VERSION_MINOR,
		PKCS11_TA_VERSION_PATCH,
	};
	size_t size = 0;

	if (ctrl || in)
		return PKCS11_BAD_PARAM;

	if (!out)
		return PKCS11_OK;

	size = out->memref.size;
	out->memref.size = sizeof(ver);

	if (size < sizeof(ver))
		return PKCS11_SHORT_BUFFER;

	if (!ALIGNMENT_IS_OK(out->memref.buffer, uint32_t))
		return PKCS11_BAD_PARAM;

	TEE_MemMove(out->memref.buffer, ver, sizeof(ver));

	return PKCS11_OK;
}

static bool ctrl_stores_output_status(uint32_t ptypes, TEE_Param *ctrl)
{
	return TEE_PARAM_TYPE_GET(ptypes, 0) == TEE_PARAM_TYPE_MEMREF_INOUT &&
	       ALIGNMENT_IS_OK(ctrl->memref.buffer, uint32_t) &&
	       ctrl->memref.size >= sizeof(uint32_t);
}

/*
 * Entry point for PKCS11 TA commands
 *
 * Param#0 ctrl, is none or an output or in/out buffer. The input data are
 * arguments of the to invoked command while the output data is used to send
 * back to the client a PKCS11 finer status ID than the GPD TEE result codes.
 * When doing so, TEE result code maybe set to TEE_SUCCESS in which case
 * client shall check the status ID from the parameter #0 output buffer.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *tee_session __unused, uint32_t cmd,
				      uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	enum pkcs11_ta_cmd command = cmd;
	TEE_Param *ctrl = NULL;
	TEE_Param *p1_in = NULL;
	TEE_Param __maybe_unused *p2_in = NULL;
	TEE_Param *p2_out = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t rc = 0;

	/* Param#0: none or in-out buffer with serialized arguments */
	switch (TEE_PARAM_TYPE_GET(ptypes, 0)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		ctrl = &params[0];
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Param#1: none or input data buffer */
	switch (TEE_PARAM_TYPE_GET(ptypes, 1)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		p1_in = &params[1];
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Param#2: none or input data buffer */
	switch (TEE_PARAM_TYPE_GET(ptypes, 2)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		p2_in = &params[2];
		break;
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		p2_out = &params[2];
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Param#3: currently unused */
	switch (TEE_PARAM_TYPE_GET(ptypes, 3)) {
	case TEE_PARAM_TYPE_NONE:
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	DMSG("%s ctrl %"PRIu32"@%p, %s %"PRIu32"@%p, %s %"PRIu32"@%p",
	     id2str_ta_cmd(cmd),
	     ctrl ? ctrl->memref.size : 0, ctrl ? ctrl->memref.buffer : 0,
	     p1_in ? "in" : "---", p1_in ? p1_in->memref.size : 0,
	     p1_in ? p1_in->memref.buffer : NULL,
	     p2_out ? "out" : (p2_in ? "in" : "---"),
	     p2_out ? p2_out->memref.size : (p2_in ? p2_in->memref.size : 0),
	     p2_out ? p2_out->memref.buffer :
		      (p2_in ? p2_in->memref.buffer : NULL));

	switch (command) {
	case PKCS11_CMD_PING:
		rc = entry_ping(ctrl, p1_in, p2_out);
		break;

	default:
		EMSG("Command 0x%"PRIx32" is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ctrl_stores_output_status(ptypes, ctrl)) {
		TEE_MemMove(ctrl->memref.buffer, &rc, sizeof(uint32_t));
		ctrl->memref.size = sizeof(uint32_t);

		res = pkcs2tee_noerr(rc);

		DMSG("%s rc 0x%08"PRIx32"/%s",
		     id2str_ta_cmd(cmd), rc, id2str_rc(rc));
	} else {
		res = pkcs2tee_error(rc);

		DMSG("%s rc 0x%08"PRIx32"/%s, TEE rc %"PRIx32,
		     id2str_ta_cmd(cmd), rc, id2str_rc(rc), res);
	}

	return res;
}
