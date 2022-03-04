// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Broadcom
 * Copyright (c) 2022, Linaro Limited
 */

#include <drivers/gic.h>
#include <drivers/wdt.h>
#include <kernel/pseudo_ta.h>
#include <pta_watchdog.h>
#include <trace.h>

static bool is_wdt_registered(void)
{
	return wdt_chip;
}

static TEE_Result pta_wdt_config(uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (exp_ptypes != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	res = watchdog_init(NULL, NULL);
	if (res)
		return res;

	watchdog_settimeout(params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result pta_wdt_start(uint32_t ptypes,
				TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (exp_ptypes != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	res = watchdog_init(NULL, NULL);
	if (res)
		return res;

	watchdog_start();

	return TEE_SUCCESS;
}

static TEE_Result pta_wdt_ping(uint32_t ptypes,
			       TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!is_wdt_registered())
		return TEE_ERROR_NOT_SUPPORTED;

	watchdog_ping();

	return TEE_SUCCESS;
}

static TEE_Result pta_wdt_stop(uint32_t ptypes,
			       TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!is_wdt_registered())
		return TEE_ERROR_NOT_SUPPORTED;

	watchdog_stop();

	return TEE_SUCCESS;
}

static TEE_Result pta_wdt_set_timeout(uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!is_wdt_registered())
		return TEE_ERROR_NOT_SUPPORTED;

	watchdog_settimeout(params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result pta_wdt_extend_timeout_caps(uint32_t ptypes,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (exp_pt != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = watchdog_extend_timeout_max();
	params[0].value.b = 0;
	params[1].value.a = 0;
	params[1].value.b = 0;

	return TEE_SUCCESS;
}

static TEE_Result pta_wdt_extend_timeout_start(uint32_t ptypes,
					       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	unsigned long timeout = params[0].value.a;

	if (exp_ptypes != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	/* 0 sec is not a valid value */
	if (!timeout)
		return TEE_ERROR_BAD_PARAMETERS;

	return watchdog_extend_timeout(timeout);
}

static TEE_Result pta_wdt_extend_timeout_stop(uint32_t ptypes,
					      TEE_Param params[] __unused)
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);

	if (exp_ptypes != ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	return watchdog_extend_timeout(0);
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	switch (cmd_id) {
	case PTA_WATCHDOG_CMD_CONFIG:
		res = pta_wdt_config(ptypes, params);
		break;
	case PTA_WATCHDOG_CMD_START:
		res = pta_wdt_start(ptypes, params);
		break;
	case PTA_WATCHDOG_CMD_PING:
		res = pta_wdt_ping(ptypes, params);
		break;
	case PTA_WATCHDOG_CMD_STOP:
		res = pta_wdt_stop(ptypes, params);
		break;
	case PTA_WATCHDOG_CMD_SET_TIMEOUT:
		res = pta_wdt_set_timeout(ptypes, params);
		break;
	case PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_CAPS:
		res = pta_wdt_extend_timeout_caps(ptypes, params);
		break;
	case PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_START:
		res = pta_wdt_extend_timeout_start(ptypes, params);
		break;
	case PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_STOP:
		res = pta_wdt_extend_timeout_stop(ptypes, params);
		break;

	default:
		EMSG("cmd: %d not supported by %s", cmd_id, PTA_WATCHDOG_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = PTA_WATCHDOG_UUID,
		   .name = PTA_WATCHDOG_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
