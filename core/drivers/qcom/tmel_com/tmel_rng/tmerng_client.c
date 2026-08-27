// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>
#include <tmecom_client.h>
#include <tmemessages_uids.h>
#include <tmerng_client.h>
#include <trace.h>
#include <types_ext.h>
/* rng_support.h relies on TEE_Result and size_t being declared first */
#include <rng_support.h>

static TEE_Result tme_rng_get_data(void *buf, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct tme_rng_get_msg msg = { };
	paddr_t rng_paddr = 0;
	void *rng_buf = NULL;

	if (!buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len > TME_RNG_MAX_LENGTH) {
		EMSG("Requested length %zu exceeds maximum %u",
		     len, TME_RNG_MAX_LENGTH);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rng_buf = tmecom_client_get_coherent_buf(len, &rng_paddr);
	if (!rng_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (rng_paddr > UINT32_MAX) {
		EMSG("RNG buffer paddr 0x%lx exceeds 32-bit range", rng_paddr);
		ret = TEE_ERROR_GENERIC;
		goto out_release;
	}

	msg.input.length = len;
	msg.output.buf = (uint32_t)rng_paddr;
	msg.output.buf_len = len;
	msg.output.buf_len_used = 0;
	msg.output.status = TME_STATUS_UNKNOWN;

	ret = tmecom_client_send_message(TME_MSG_UID_HCS_RNG_GET,
					 TME_MSG_UID_HCS_RNG_GET_PARAM_ID,
					 true, TMECOM_DEFAULT_TIMEOUT,
					 &msg, sizeof(msg),
					 NULL, NULL, NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME RNG IPC failed: 0x%x", ret);
		goto out_release;
	}

	ret = tme_status_to_tee_result(msg.output.status);
	if (ret != TEE_SUCCESS) {
		EMSG("TME RNG failed, status: 0x%x", msg.output.status);
		goto out_release;
	}

	if (msg.output.buf_len_used != len) {
		EMSG("TME returned %u bytes, expected %zu",
		     msg.output.buf_len_used, len);
		ret = TEE_ERROR_GENERIC;
		goto out_release;
	}

	memcpy(buf, rng_buf, len);

out_release:
	tmecom_client_release_buf();
	return ret;
}

TEE_Result tme_hw_get_random_bytes(void *buf, size_t len)
{
	uint8_t *output = buf;
	TEE_Result res = TEE_SUCCESS;
	size_t filled = 0;

	if (!buf || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	while (filled < len) {
		size_t chunk = MIN(len - filled, (size_t)TME_RNG_MAX_LENGTH);

		res = tme_rng_get_data(output + filled, chunk);
		if (res != TEE_SUCCESS)
			return res;

		filled += chunk;
	}

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	return tme_hw_get_random_bytes(buf, len);
}
