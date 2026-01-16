// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, STMicroelectronics - All Rights Reserved
 */

#include <drivers/stm32_bsec.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <pta_stm32mp_debug_access.h>

#define PTA_NAME	"debug_access.pta"

static_assert(IS_ENABLED(CFG_STM32_BSEC));

static TEE_Result pta_dbg_grant_dbg_access(uint32_t param_types,
					   TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t ext_param = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	unsigned int dbg_profile = params[0].value.a;

	if (param_types != ext_param)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (dbg_profile) {
	case PTA_STM32_DEBUG_HDP_DBG_PROFILE:
		if (!stm32_bsec_hdp_is_enabled())
			return TEE_ERROR_ACCESS_DENIED;
		break;
	case PTA_STM32_DEBUG_PERIPHERAL_DBG_PROFILE:
		if (!stm32_bsec_coresight_is_enabled())
			return TEE_ERROR_ACCESS_DENIED;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result pta_dbg_access_invoke_cmd(void *pSessionContext __unused,
					    uint32_t cmd_id,
					    uint32_t param_types,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32,
	     cmd_id, param_types);

	switch (cmd_id) {
	case PTA_STM32_DEBUG_CMD_GRANT_DBG_ACCESS:
		return pta_dbg_grant_dbg_access(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result
pta_dbg_access_open_session(uint32_t ptypes __unused,
			    TEE_Param par[TEE_NUM_PARAMS] __unused,
			    void **session __unused)
{
	uint32_t login = to_ta_session(ts_get_current_session())->clnt_id.login;

	if (login == TEE_LOGIN_REE_KERNEL)
		return TEE_SUCCESS;

	return TEE_ERROR_ACCESS_DENIED;
}

pseudo_ta_register(.uuid = PTA_STM32_DBG_ACCESS_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT |
			    TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = pta_dbg_access_open_session,
		   .invoke_command_entry_point = pta_dbg_access_invoke_cmd);
