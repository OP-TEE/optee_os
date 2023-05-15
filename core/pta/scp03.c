// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto_se.h>
#include <kernel/pseudo_ta.h>
#include <pta_scp03.h>

#define PTA_NAME "pta.scp03"

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t command_id, uint32_t pt,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	bool rotate_keys = false;

	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (command_id) {
	case PTA_CMD_ENABLE_SCP03:
		if (params[0].value.a == PTA_SCP03_SESSION_ROTATE_KEYS)
			rotate_keys = true;

		return crypto_se_enable_scp03(rotate_keys);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SCP03_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
