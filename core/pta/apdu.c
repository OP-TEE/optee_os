// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2021 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
#include <crypto/crypto_se.h>
#include <kernel/pseudo_ta.h>
#include <pta_apdu.h>

#define PTA_NAME "pta.apdu"

static TEE_Result get_apdu_type(uint32_t val, enum crypto_apdu_type *type)
{
	switch (val) {
	case PTA_APDU_TXRX_CASE_NO_HINT:
		*type = CRYPTO_APDU_CASE_NO_HINT;
		break;
	case PTA_APDU_TXRX_CASE_1:
		*type = CRYPTO_APDU_CASE_1;
		break;
	case PTA_APDU_TXRX_CASE_2:
		*type = CRYPTO_APDU_CASE_2;
		break;
	case PTA_APDU_TXRX_CASE_2E:
		*type = CRYPTO_APDU_CASE_2E;
		break;
	case PTA_APDU_TXRX_CASE_3:
		*type = CRYPTO_APDU_CASE_3;
		break;
	case PTA_APDU_TXRX_CASE_3E:
		*type = CRYPTO_APDU_CASE_3E;
		break;
	case PTA_APDU_TXRX_CASE_4:
		*type = CRYPTO_APDU_CASE_4;
		break;
	case PTA_APDU_TXRX_CASE_4E:
		*type = CRYPTO_APDU_CASE_4E;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t command_id, uint32_t pt,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT);
	enum crypto_apdu_type type = CRYPTO_APDU_CASE_NO_HINT;
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	size_t len = 0;

	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (command_id) {
	case PTA_CMD_TXRX_APDU_RAW_FRAME:
		ret = get_apdu_type(params[0].value.a, &type);
		if (ret)
			return ret;

		len = params[3].memref.size;
		ret = crypto_se_do_apdu(type,
					params[1].memref.buffer,
					params[1].memref.size,
					params[2].memref.buffer,
					params[2].memref.size,
					params[3].memref.buffer,
					&len);
		if (!ret)
			params[3].memref.size = len;
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return ret;
}

pseudo_ta_register(.uuid = PTA_APDU_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
