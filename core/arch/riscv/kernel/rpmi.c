// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/rpmi_mailbox.h>
#include <io.h>
#include <rpmi.h>
#include <tee_api_defines_extensions.h>

/* Return exchange errors separately from the firmware service status. */
TEE_Result rpmi_send_with_status(struct mbox_chan *channel,
				 uint32_t service_id, void *req,
				 size_t req_len, void *resp,
				 size_t *resp_len, int32_t *status)
{
	struct rpmi_mbox_message msg = {};
	TEE_Result res = TEE_SUCCESS;

	rpmi_mbox_init_send_with_response(&msg, service_id, req, req_len,
					  resp, *resp_len);
	res = rpmi_mbox_send_message_sync(channel, &msg);
	if (res)
		return res;

	/* Error responses may contain only the status word. */
	if (msg.data.out_response_len < sizeof(uint32_t))
		return TEE_ERROR_BAD_FORMAT;

	*resp_len = msg.data.out_response_len;
	*status = (int32_t)get_unaligned_le32(resp);

	return TEE_SUCCESS;
}

TEE_Result rpmi_status_to_tee_result(int32_t status)
{
	switch (status) {
	case RPMI_SUCCESS:
		return TEE_SUCCESS;
	case RPMI_ERR_NOTSUPP:
		return TEE_ERROR_NOT_SUPPORTED;
	case RPMI_ERR_INVALID_PARAM:
	case RPMI_ERR_INVALID_ADDR:
	case RPMI_ERR_BAD_RANGE:
		return TEE_ERROR_BAD_PARAMETERS;
	case RPMI_ERR_DENIED:
		return TEE_ERROR_ACCESS_DENIED;
	case RPMI_ERR_ALREADY:
	case RPMI_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case RPMI_ERR_BUSY:
		return TEE_ERROR_BUSY;
	case RPMI_ERR_TIMEOUT:
		return TEE_ERROR_TIMEOUT;
	case RPMI_ERR_IO:
		return TEE_ERROR_COMMUNICATION;
	case RPMI_ERR_NO_DATA:
		return TEE_ERROR_NO_DATA;
	default:
		return TEE_ERROR_GENERIC;
	}
}
