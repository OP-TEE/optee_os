// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019-2021, Linaro Limited
 * Copyright (c) 2019-2021, STMicroelectronics
 */
#include <compiler.h>
#include <config.h>
#include <confine_array_index.h>
#include <drivers/scmi-msg.h>
#include <kernel/pseudo_ta.h>
#include <pta_scmi_client.h>
#include <stdint.h>
#include <string.h>

static TEE_Result cmd_capabilities(void *session __unused, uint32_t ptypes,
				   TEE_Param param[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	param[0].value.a = PTA_SCMI_CAPS_NONE;

	if (IS_ENABLED(CFG_SCMI_MSG_SMT))
		param[0].value.a |= PTA_SCMI_CAPS_SMT_HEADER;

	return TEE_SUCCESS;
}

static TEE_Result cmd_process_smt_channel(void *sess __unused, uint32_t ptypes,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	uint32_t channel_id = (int)params[0].value.a;

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED(CFG_SCMI_MSG_SMT)) {
		scmi_smt_threaded_entry(channel_id);
		return TEE_SUCCESS;
	}

	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result cmd_process_smt_message(void *sess __unused, uint32_t ptypes,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_MEMREF_INOUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	uint32_t __unused channel_id = (int)params[0].value.a;
	TEE_Param __unused *param1 = params + 1;

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result cmd_get_channel(void *sess __unused, uint32_t ptypes,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);
	uint32_t __maybe_unused channel_id = (int)params[0].value.a;
	uint32_t caps = (int)params[0].value.b;

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("channel %"PRIu32, channel_id);

	if (IS_ENABLED(CFG_SCMI_MSG_SMT)) {
		if (caps == PTA_SCMI_CAPS_SMT_HEADER) {
			/* Channel handle (value[0].a) is channel ID */
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result pta_scmi_session(uint32_t ptypes __unused,
				   TEE_Param params[TEE_NUM_PARAMS] __unused,
				   void **session __unused)
{
	struct ts_session *ts = ts_get_current_session();
	struct tee_ta_session *ta_session = to_ta_session(ts);

	FMSG("ptypes %#"PRIx32, ptypes);

	/* Only REE kernel is allowed to access SCMI resources */
	if (ta_session->clnt_id.login != TEE_LOGIN_REE_KERNEL) {
		DMSG("Expecting TEE_LOGIN_REE_KERNEL");
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (IS_ENABLED(CFG_SCMI_MSG_SMT))
		return TEE_SUCCESS;

	return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result pta_scmi_command(void *session, uint32_t cmd, uint32_t ptypes,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG("SCMI command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_SCMI_CMD_CAPABILITIES:
		return cmd_capabilities(session, ptypes, params);
	case PTA_SCMI_CMD_PROCESS_SMT_CHANNEL:
		return cmd_process_smt_channel(session, ptypes, params);
	case PTA_SCMI_CMD_PROCESS_SMT_CHANNEL_MESSAGE:
		return cmd_process_smt_message(session, ptypes, params);
	case PTA_SCMI_CMD_GET_CHANNEL:
		return cmd_get_channel(session, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_SCMI_UUID, .name = PTA_SCMI_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT |
			    TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = pta_scmi_session,
		   .invoke_command_entry_point = pta_scmi_command);
