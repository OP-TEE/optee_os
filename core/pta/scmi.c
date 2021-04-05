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
#include <optee_rpc_cmd.h>
#include <pta_scmi_client.h>
#include <stdint.h>
#include <string.h>
#include <tee/uuid.h>
#include <util.h>

static bool valid_caps(unsigned int caps)
{
	return (caps & ~PTA_SCMI_CAPS_VALID_MASK) == 0;
}

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
	if (IS_ENABLED(CFG_CORE_OCALL))
		param[0].value.a |= PTA_SCMI_CAPS_OCALL_THREAD;

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
	uint32_t channel_id = (int)params[0].value.a;
	TEE_Param *param1 = params + 1;

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED(CFG_SCMI_MSG_SMT)) {
		struct scmi_msg_channel *channel = NULL;

		channel = plat_scmi_get_channel(channel_id);
		if (!channel)
			return TEE_ERROR_BAD_PARAMETERS;

		/*
		 * Caller provides the buffer, we bind channel to that buffer.
		 * Once message is processed, unbind the buffer since it is
		 * valid only for the current invocation.
		 */
		scmi_smt_set_shared_buffer(channel, param1->memref.buffer);
		scmi_smt_threaded_entry(channel_id);
		scmi_smt_set_shared_buffer(channel, NULL);

		return TEE_SUCCESS;
	}

	return TEE_ERROR_NOT_SUPPORTED;
}

/* Process an OCALL RPC to client and report status */
static enum optee_scmi_ocall_reply pta_scmi_ocall(uint32_t channel_id)
{
	static const TEE_UUID uuid = PTA_SCMI_UUID;
	static uint64_t uuid_octet[2];
	static bool uuid_ready;
	struct thread_param params[THREAD_RPC_MAX_NUM_PARAMS] = {
		/* Ocall command, sub command */
		THREAD_PARAM_VALUE(INOUT, 0, 0, 0),
		/* UUID of Ocall initiator */
		THREAD_PARAM_VALUE(IN, 0, 0, 0),
		/* Output value argument to get REE feedback */
		THREAD_PARAM_VALUE(OUT, 0, 0, 0),
	};
	uint64_t ocall_res = 0;
	uint64_t __maybe_unused ocall_ori = 0;
	enum optee_scmi_ocall_reply agent_request = PTA_SCMI_OCALL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!IS_ENABLED(CFG_CORE_OCALL))
		return PTA_SCMI_OCALL_ERROR;

	if (!uuid_ready) {
		tee_uuid_to_octets((uint8_t *)uuid_octet, &uuid);
		uuid_ready = true;
	}

	params[0].u.value.a = PTA_SCMI_OCALL_CMD_THREAD_READY;
	params[1].u.value.a = uuid_octet[0];
	params[1].u.value.b = uuid_octet[1];

	params[0] = THREAD_PARAM_VALUE(INOUT, PTA_SCMI_OCALL_CMD_THREAD_READY,
				       0, 0);
	params[1] = THREAD_PARAM_VALUE(IN, uuid_octet[0], uuid_octet[1], 0);
	params[2] = THREAD_PARAM_VALUE(OUT, 0, 0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_OCALL, ARRAY_SIZE(params), params);
	if (res) {
		DMSG("Close thread on RPC error %#"PRIx32, res);
		return PTA_SCMI_OCALL_ERROR;
	}

	ocall_res = params[0].u.value.b;
	ocall_ori = params[0].u.value.c;
	if (ocall_res) {
		DMSG("SCMI RPC thread failed %#"PRIx64" from %#"PRIx64,
		     ocall_res, ocall_ori);
		return PTA_SCMI_OCALL_ERROR;
	}

	agent_request = (enum optee_scmi_ocall_reply)params[2].u.value.a;

	switch (agent_request) {
	case PTA_SCMI_OCALL_PROCESS_SMT_CHANNEL:
		FMSG("Posting message on channel %u"PRIu32, channel_id);
		if (IS_ENABLED(CFG_SCMI_MSG_SMT))
			scmi_smt_threaded_entry(channel_id);
		else
			panic();
		break;
	case PTA_SCMI_OCALL_CLOSE_THREAD:
		FMSG("Closing channel %u"PRIu32, channel_id);
		break;
	case PTA_SCMI_OCALL_ERROR:
		FMSG("Error on channel %u"PRIu32, channel_id);
		break;
	default:
		DMSG("Invalid Ocall cmd %#x on channel %u"PRIu32,
		     agent_request, channel_id);
		return PTA_SCMI_OCALL_CLOSE_THREAD;
	}

	return agent_request;
}

static TEE_Result cmd_scmi_ocall_thread(void *sess __unused, uint32_t ptypes,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE,
						    TEE_PARAM_TYPE_NONE);

	uint32_t channel_id = (int)params[0].value.a;
	struct scmi_msg_channel *channel = NULL;

	if (ptypes != exp_ptypes)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED(CFG_SCMI_MSG_SMT))
		channel = plat_scmi_get_channel(channel_id);
	else
		return TEE_ERROR_NOT_SUPPORTED;

	if (!channel)
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("Enter Ocall thread on channel %u"PRIu32, channel_id);
	while (1) {
		switch (pta_scmi_ocall(channel_id)) {
		case PTA_SCMI_OCALL_PROCESS_SMT_CHANNEL:
			continue;
		case PTA_SCMI_OCALL_CLOSE_THREAD:
			return TEE_SUCCESS;
		default:
			return TEE_ERROR_GENERIC;
		}
	}
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

	if (ptypes != exp_ptypes || !valid_caps(caps))
		return TEE_ERROR_BAD_PARAMETERS;

	FMSG("channel %"PRIu32, channel_id);

	if (IS_ENABLED(CFG_SCMI_MSG_SMT)) {
		if (caps & PTA_SCMI_CAPS_SMT_HEADER) {
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
	case PTA_SCMI_CMD_OCALL_THREAD:
		return cmd_scmi_ocall_thread(session, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_SCMI_UUID, .name = PTA_SCMI_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT |
			    TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = pta_scmi_session,
		   .invoke_command_entry_point = pta_scmi_command);
