// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Pseudo TA that exposes the discrete TPM owned by OP-TEE to the normal
 * world as a TPM transport. It advertises itself on the OP-TEE device bus
 * (TA_FLAG_DEVICE_ENUM) so the Linux TEE-backed TPM driver can bind to it
 * by UUID and pipe raw TPM2 commands through to the in-core driver (the
 * SPI TIS chip driver). This is the discrete-TPM analogue of the fTPM TA's
 * SUBMIT_COMMAND, using a distinct UUID rather than the fTPM one.
 */

#include <drivers/tpm2_chip.h>
#include <kernel/mutex.h>
#include <kernel/pseudo_ta.h>
#include <pta_tpm_passthrough.h>
#include <string.h>
#include <tee_api_defines.h>
#include <trace.h>

#define PTA_NAME "tpm_passthrough.pta"

/*
 * Serialise transceive against other in-core users of the single TPM chip
 * (e.g. the TCG event-log provider), and against concurrent REE callers.
 */
static struct mutex tpm_lock = MUTEX_INITIALIZER;

static TEE_Result tpm_pta_submit(uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_INOUT,
				       TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE);
	uint8_t *cmd = params[0].memref.buffer;
	uint32_t cmd_len = params[0].memref.size;
	uint8_t *resp = params[1].memref.buffer;
	uint32_t resp_len = params[1].memref.size;
	enum tpm2_result res = TPM2_OK;

	if (ptypes != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!cmd || !cmd_len || !resp || !resp_len)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&tpm_lock);

	res = tpm2_chip_send(cmd, cmd_len);
	if (res) {
		mutex_unlock(&tpm_lock);
		EMSG("TPM passthrough: send failed (%d)", res);
		return TEE_ERROR_COMMUNICATION;
	}

	res = tpm2_chip_recv(resp, &resp_len, TPM2_CMD_DURATION_DEFAULT);

	mutex_unlock(&tpm_lock);

	if (res == TPM2_ERR_SHORT_BUFFER) {
		/* resp_len now holds the required length */
		params[1].memref.size = resp_len;
		return TEE_ERROR_SHORT_BUFFER;
	}
	if (res) {
		EMSG("TPM passthrough: recv failed (%d)", res);
		return TEE_ERROR_COMMUNICATION;
	}

	params[1].memref.size = resp_len;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_TPM_PASSTHROUGH_SUBMIT_COMMAND:
		return tpm_pta_submit(ptypes, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static TEE_Result open_session(uint32_t ptypes __unused,
			       TEE_Param par[TEE_NUM_PARAMS] __unused,
			       void **session __unused)
{
	struct ts_session *ts = ts_get_current_session();
	struct tee_ta_session *ta_session = to_ta_session(ts);

	/*
	 * The discrete TPM is a shared security resource: raw command access
	 * lets a caller reset PCRs or alter hierarchies and so defeat measured
	 * boot. The passthrough exists only to carry the normal-world kernel's
	 * TPM stack, so restrict it to the REE kernel and reject other TAs and
	 * REE user space.
	 */
	if (ta_session->clnt_id.login != TEE_LOGIN_REE_KERNEL)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

pseudo_ta_register(.uuid = PTA_TPM_PASSTHROUGH_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
