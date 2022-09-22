// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Broadcom
 */

#include <config.h>
#include <drivers/bcm_sotp.h>
#include <io.h>
#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>

#define SOTP_SERVICE_UUID \
		{0x6272636D, 0x2018, 0x1101,  \
		{0x42, 0x43, 0x4D, 0x5F, 0x53, 0x4F, 0x54, 0x50} }

enum pta_bcm_sotp_cmd {
	PTA_BCM_SOTP_CMD_READ = 0,
	PTA_BCM_SOTP_CMD_WRITE,
};

#define SOTP_TA_NAME		"pta_bcm_sotp.ta"

static bool sotp_access_disabled;

/**
 * close_session() - Print a debug message when closing a session and set the
 *		     driver to disallow any more pta sessions to connect.
 * @pSessionContext	Unused.
 */
static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for \"%s\"", SOTP_TA_NAME);
	if (IS_ENABLED(CFG_BCM_SOTP_SINGLE_SESSION))
		sotp_access_disabled = true;
}

static TEE_Result pta_sotp_read(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint64_t sotp_row_value = 0;
	uint32_t val = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	val = params[0].value.a;

	bcm_iproc_sotp_mem_read(val, true, &sotp_row_value);
	reg_pair_from_64(sotp_row_value, &params[1].value.a,
			 &params[1].value.b);

	return TEE_SUCCESS;
}

static TEE_Result pta_sotp_write(uint32_t param_types __unused,
				 TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	/* Nothing as of now */
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, SOTP_TA_NAME);

	if (IS_ENABLED(CFG_BCM_SOTP_SINGLE_SESSION) && sotp_access_disabled) {
		DMSG("bcm sotp pta access disabled");
		return TEE_ERROR_ACCESS_DENIED;
	}

	switch (cmd_id) {
	case PTA_BCM_SOTP_CMD_READ:
		res = pta_sotp_read(param_types, params);
		break;
	case PTA_BCM_SOTP_CMD_WRITE:
		res = pta_sotp_write(param_types, params);
		break;
	default:
		EMSG("cmd %d Not supported %s", cmd_id, SOTP_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = SOTP_SERVICE_UUID,
		   .name = SOTP_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
