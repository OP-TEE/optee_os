// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <rpmi_reqfwd.h>
#include <stdlib.h>
#include <string.h>
#include <utee_defines.h>
#include <util.h>

struct rpmi_reqfwd_retrieve_req {
	uint32_t start_index;
};

struct rpmi_reqfwd_retrieve_resp {
	int32_t status;
	uint32_t remaining;
	uint32_t returned;
	uint8_t data[];
};

struct rpmi_reqfwd_complete_resp {
	int32_t status;
	uint32_t num_messages;
};

/* Validate the service group once before a retrieve or complete operation. */
static TEE_Result reqfwd_check_channel(struct mbox_chan *channel)
{
	uint32_t group = 0;
	TEE_Result res = TEE_SUCCESS;

	res = rpmi_mbox_get_attribute(channel, RPMI_MBOX_ATTR_SERVICEGROUP_ID,
				      &group);
	if (res)
		return res;
	if (group != RPMI_SRVGRP_REQUEST_FORWARD)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

TEE_Result rpmi_reqfwd_retrieve(struct mbox_chan *channel,
				void *data, size_t data_len_max, size_t *len)
{
	struct rpmi_reqfwd_retrieve_req req = {};
	struct rpmi_reqfwd_retrieve_resp *resp = NULL;
	uint32_t service_id = RPMI_REQFWD_RETRIEVE_CURRENT_MESSAGE;
	uint32_t max_msg_data_size = 0;
	size_t response_len_max = 0;
	size_t offset = 0;
	size_t total = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!channel || !data || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	*len = 0;

	res = reqfwd_check_channel(channel);
	if (res)
		return res;

	res = rpmi_mbox_get_attribute(channel, RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE,
				      &max_msg_data_size);
	if (res)
		return res;

	response_len_max = max_msg_data_size;
	if (response_len_max <= sizeof(*resp))
		return TEE_ERROR_NOT_SUPPORTED;

	resp = malloc(response_len_max);
	if (!resp)
		return TEE_ERROR_OUT_OF_MEMORY;

	while (true) {
		size_t response_len = response_len_max;
		int32_t status = RPMI_ERR_FAILED;
		uint32_t remaining = 0;
		uint32_t returned = 0;
		uint64_t end = 0;

		req.start_index = TEE_U32_TO_LITTLE_ENDIAN(offset);
		res = rpmi_send_with_status(channel, service_id, &req,
					    sizeof(req), resp, &response_len,
					    &status);
		if (res)
			break;

		res = rpmi_status_to_tee_result(status);
		if (res)
			break;
		/* Success requires both remaining and returned byte counts. */
		if (response_len < sizeof(*resp)) {
			res = TEE_ERROR_BAD_FORMAT;
			break;
		}

		remaining = TEE_U32_FROM_LITTLE_ENDIAN(resp->remaining);
		returned = TEE_U32_FROM_LITTLE_ENDIAN(resp->returned);
		if (!returned || returned != response_len - sizeof(*resp)) {
			res = TEE_ERROR_BAD_FORMAT;
			break;
		}

		end = (uint64_t)offset + returned + remaining;
		if (end > UINT32_MAX) {
			res = TEE_ERROR_BAD_FORMAT;
			break;
		}

		/* The total message length must be the same for every chunk. */
		if (!offset) {
			total = end;
			if (total > data_len_max) {
				res = TEE_ERROR_SHORT_BUFFER;
				break;
			}
		} else if (end != total) {
			res = TEE_ERROR_BAD_FORMAT;
			break;
		}

		memcpy((uint8_t *)data + offset, resp->data, returned);
		offset += returned;
		if (!remaining) {
			*len = offset;
			break;
		}
	}

	free(resp);

	return res;
}

TEE_Result rpmi_reqfwd_complete(struct mbox_chan *channel,
				void *data, size_t len, uint32_t *num_messages)
{
	struct rpmi_reqfwd_complete_resp resp = {};
	size_t response_len = sizeof(resp);
	int32_t status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	if ((!data && len) || !num_messages)
		return TEE_ERROR_BAD_PARAMETERS;

	*num_messages = 0;

	res = reqfwd_check_channel(channel);
	if (res)
		return res;

	res = rpmi_send_with_status(channel,
				    RPMI_REQFWD_COMPLETE_CURRENT_MESSAGE,
				    data, len, &resp, &response_len, &status);
	if (res)
		return res;

	res = rpmi_status_to_tee_result(status);
	if (res)
		return res;
	/* Success requires the status and pending-message count. */
	if (response_len != sizeof(resp))
		return TEE_ERROR_BAD_FORMAT;

	*num_messages = TEE_U32_FROM_LITTLE_ENDIAN(resp.num_messages);

	return TEE_SUCCESS;
}
