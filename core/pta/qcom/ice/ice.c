// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <pta_qcom_ice.h>
#include <tee_api_defines_extensions.h>
#include <trace.h>

#include "sw_keys/ice_sw_keys.h"

/*
 * Controller-agnostic entry points. These wrap the per-controller
 * implementation so the dispatcher stays independent of the underlying ICE
 * block. Only software-key programming exists today; a future hardware-key
 * (HWKM) path can be selected here at runtime, based on the key size passed
 * to the PTA, dispatching to hwkm_cmd_ice_*() instead of sw_cmd_ice_*().
 */
static TEE_Result cmd_ice_invalidate_key(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	return sw_cmd_ice_invalidate_key(param_types, params);
}

static TEE_Result cmd_ice_set_config_key(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	return sw_cmd_ice_set_config_key(param_types, params);
}

/* PTA command dispatcher */
static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_CMD_ICE_INVALIDATE_KEY:
		return cmd_ice_invalidate_key(param_types, params);
	case PTA_CMD_ICE_SET_CONFIG_KEY:
		return cmd_ice_set_config_key(param_types, params);
	default:
		break;
	}

	EMSG("ICE: Command not implemented: %u", cmd_id);
	return TEE_ERROR_NOT_IMPLEMENTED;
}

/* Only the REE kernel's storage-encryption path may open a session */
static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct tee_ta_session *s = to_ta_session(ts_get_current_session());

	if (s->clnt_id.login != TEE_LOGIN_REE_KERNEL)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = PTA_QCOM_ICE_UUID,
		   .name = "qcom_ice.pta",
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
