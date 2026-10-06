// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <rpmi_tee.h>
#include <stdlib.h>
#include <utee_defines.h>
#include <util.h>

/* Shared channel helpers. */

/* Check that the channel belongs to the TEE service group. */
static TEE_Result tee_check_channel(struct mbox_chan *channel)
{
	uint32_t group = 0;
	TEE_Result res = TEE_SUCCESS;

	res = rpmi_mbox_get_attribute(channel, RPMI_MBOX_ATTR_SERVICEGROUP_ID,
				      &group);
	if (res)
		return res;
	if (group != RPMI_TEE_SERVICEGROUP_ID)
		return TEE_ERROR_NOT_SUPPORTED;

	return TEE_SUCCESS;
}

/* Separate local exchange errors from the firmware's RPMI service status. */
static TEE_Result tee_send_with_status(struct mbox_chan *channel,
				       uint32_t service_id, void *req,
				       size_t req_len, void *resp,
				       size_t *resp_len, int32_t *status)
{
	TEE_Result res = TEE_SUCCESS;

	res = tee_check_channel(channel);
	if (res)
		return res;

	return rpmi_send_with_status(channel, service_id, req, req_len,
				     resp, resp_len, status);
}

/* Discovery. */

struct rpmi_tee_probe_features_req {
	uint32_t feature_id;
};

struct rpmi_tee_probe_features_resp {
	int32_t status;
	uint32_t value;
};

struct rpmi_tee_probe_system_resp {
	int32_t status;
	uint32_t caller_domain;
	uint32_t caller_endpoint;
	uint32_t domain_count;
	uint32_t domains[];
};

TEE_Result rpmi_tee_probe_features(struct mbox_chan *channel,
				   uint32_t feature_id, uint32_t *value)
{
	struct rpmi_tee_probe_features_req req = {};
	struct rpmi_tee_probe_features_resp resp = {};
	size_t resp_len = sizeof(resp);
	int32_t status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	if (!channel || !value)
		return TEE_ERROR_BAD_PARAMETERS;

	*value = 0;

	req.feature_id = TEE_U32_TO_LITTLE_ENDIAN(feature_id);
	res = tee_send_with_status(channel, RPMI_TEE_PROBE_FEATURES, &req,
				   sizeof(req), &resp, &resp_len, &status);
	if (res)
		return res;
	res = rpmi_status_to_tee_result(status);
	if (res)
		return res;
	if (resp_len != sizeof(resp))
		return TEE_ERROR_BAD_FORMAT;

	*value = TEE_U32_FROM_LITTLE_ENDIAN(resp.value);

	return TEE_SUCCESS;
}

TEE_Result rpmi_tee_probe_system(struct mbox_chan *channel,
				 uint32_t *domain_id, uint32_t *ep_id)
{
	struct rpmi_tee_probe_system_resp *resp = NULL;
	uint32_t max_msg_data_size = 0;
	size_t resp_len = 0;
	uint32_t domain_count = 0;
	int32_t status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	if (!channel || !domain_id || !ep_id)
		return TEE_ERROR_BAD_PARAMETERS;

	*domain_id = 0;
	*ep_id = 0;

	res = rpmi_mbox_get_attribute(channel, RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE,
				      &max_msg_data_size);
	if (res)
		return res;

	resp_len = max_msg_data_size;
	if (resp_len < sizeof(*resp))
		return TEE_ERROR_NOT_SUPPORTED;

	resp = malloc(resp_len);
	if (!resp)
		return TEE_ERROR_OUT_OF_MEMORY;
	/* TEE_PROBE_SYSTEM has no request data. */
	res = tee_send_with_status(channel, RPMI_TEE_PROBE_SYSTEM, NULL, 0,
				   resp, &resp_len, &status);
	if (res)
		goto out;
	res = rpmi_status_to_tee_result(status);
	if (res)
		goto out;
	if (resp_len < sizeof(*resp)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	domain_count = TEE_U32_FROM_LITTLE_ENDIAN(resp->domain_count);
	if ((resp_len - sizeof(*resp)) % sizeof(uint32_t) ||
	    domain_count != (resp_len - sizeof(*resp)) / sizeof(uint32_t)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	*domain_id = TEE_U32_FROM_LITTLE_ENDIAN(resp->caller_domain);
	*ep_id = TEE_U32_FROM_LITTLE_ENDIAN(resp->caller_endpoint);

out:
	free(resp);
	return res;
}
