// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tmel_com_client.h>
#include <tmel_messages_uids.h>
#include <tmel_rng_client.h>
#include <trace.h>
#include <types_ext.h>
/* rng_support.h relies on TEE_Result and size_t being declared first */
#include <rng_support.h>

static TEE_Result tmel_rng_get_data(void *buf, size_t len)
{
	struct tmel_com_data data = { .out = buf, .out_len = len };
	struct tmel_rng_get_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len > TMEL_RNG_MAX_LENGTH) {
		EMSG("Requested length %zu exceeds maximum %u",
		     len, TMEL_RNG_MAX_LENGTH);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	msg.input.length = len;
	msg.output.buf = tmel_com_client_data_pa();
	msg.output.buf_len = len;
	msg.output.buf_len_used = 0;
	msg.output.status = TME_STATUS_UNKNOWN;

	ret = tmel_com_client_send_message(TME_MSG_UID_HCS_RNG_GET,
					   TMEL_COM_DEFAULT_TIMEOUT,
					   &msg, sizeof(msg), &data);
	if (ret != TEE_SUCCESS) {
		EMSG("TME RNG IPC failed: 0x%x", ret);
		return ret;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS) {
		EMSG("TME RNG failed, status: 0x%x", msg.output.status);
		return ret;
	}

	if (msg.output.buf_len_used != len) {
		EMSG("TME returned %u bytes, expected %zu",
		     msg.output.buf_len_used, len);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result tmel_rng_get_random_bytes(void *buf, size_t len)
{
	uint8_t *output = buf;
	TEE_Result res = TEE_SUCCESS;
	size_t filled = 0;

	if (!buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	while (filled < len) {
		size_t chunk = MIN(len - filled, TMEL_RNG_MAX_LENGTH);

		res = tmel_rng_get_data(output + filled, chunk);
		if (res != TEE_SUCCESS)
			return res;

		filled += chunk;
	}

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	return tmel_rng_get_random_bytes(buf, len);
}
