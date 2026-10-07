// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <rpmi_tee.h>
#include <stdlib.h>
#include <string.h>
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

/* CALL. */

struct rpmi_tee_call_req {
	uint32_t sender_id;
	uint32_t target_id;
	uint8_t service[16];
	uint32_t data_len;
	uint8_t data[];
} __packed;

struct rpmi_tee_call_resp {
	int32_t status;
	uint32_t data_len;
	uint8_t data[];
} __packed;

TEE_Result rpmi_tee_call_get_args(const void *request, size_t request_len,
				  uint32_t *sender_id, uint32_t *target_id,
				  const uint8_t **service,
				  const void **service_data,
				  size_t *service_len)
{
	const struct rpmi_tee_call_req *req = request;
	size_t len = 0;

	if (!sender_id || !target_id || !service ||
	    !service_data || !service_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (request_len < sizeof(*req))
		return TEE_ERROR_BAD_FORMAT;

	len = get_unaligned_le32(&req->data_len);
	if (len != request_len - sizeof(*req))
		return TEE_ERROR_BAD_FORMAT;

	*sender_id = get_unaligned_le32(&req->sender_id);
	*target_id = get_unaligned_le32(&req->target_id);
	*service = req->service;
	*service_data = req->data;
	*service_len = len;

	return TEE_SUCCESS;
}

TEE_Result rpmi_tee_call_set_response(int32_t status,
				      const void *service_data,
				      size_t service_len,
				      void *response, size_t *response_len)
{
	struct rpmi_tee_call_resp *resp = response;

	if ((!service_data && service_len) || service_len > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (*response_len < sizeof(*resp) ||
	    service_len > *response_len - sizeof(*resp))
		return TEE_ERROR_SHORT_BUFFER;

	put_unaligned_le32(&resp->status, status);
	put_unaligned_le32(&resp->data_len, service_len);
	if (service_len)
		memcpy(resp->data, service_data, service_len);

	*response_len = sizeof(*resp) + service_len;

	return TEE_SUCCESS;
}

/* Discovery. */

struct rpmi_tee_probe_features_req {
	uint32_t feature_id;
};

struct rpmi_tee_probe_features_resp {
	int32_t status;
	uint32_t value;
};

struct rpmi_tee_probe_self_resp {
	int32_t status;
	uint32_t endpoint_id;
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

TEE_Result rpmi_tee_probe_self(struct mbox_chan *channel, uint32_t *ep_id)
{
	struct rpmi_tee_probe_self_resp resp = {};
	size_t resp_len = sizeof(resp);
	int32_t status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	if (!channel || !ep_id)
		return TEE_ERROR_BAD_PARAMETERS;

	*ep_id = 0;
	res = tee_send_with_status(channel, RPMI_TEE_PROBE_SELF, NULL, 0,
				   &resp, &resp_len, &status);
	if (res)
		return res;
	res = rpmi_status_to_tee_result(status);
	if (res)
		return res;
	if (resp_len != sizeof(resp))
		return TEE_ERROR_BAD_FORMAT;

	*ep_id = TEE_U32_FROM_LITTLE_ENDIAN(resp.endpoint_id);
	return TEE_SUCCESS;
}

/* Memory parcels. */

struct rpmi_tee_memory_accept_req {
	uint32_t parcel_id;
	uint32_t nonce;
	uint32_t acceptor_id;
	uint32_t access;
	uint32_t creator_id;
	uint32_t creator_access;
	uint32_t flags;
	uint32_t address_high;
	uint32_t address_low;
	uint32_t max_pages;
	uint32_t other_count;
};

/* PAGE_CNT precedes the returned and remaining block counts. */
struct rpmi_tee_memory_accept_resp {
	int32_t status;
	uint32_t page_count;
	uint32_t returned;
	uint32_t remaining;
	uint32_t blocks[];
};

struct rpmi_tee_memory_accept_memory_req {
	uint32_t parcel_id;
	uint32_t start_index;
};

struct rpmi_tee_memory_accept_memory_resp {
	int32_t status;
	uint32_t returned;
	uint32_t remaining;
	uint32_t blocks[];
};

struct rpmi_tee_memory_release_req {
	uint32_t parcel_id;
	uint32_t flags;
	uint32_t ep_count;
	uint32_t ep_id;
};

/* BLOCK_LOW stores the number of pages minus one in its low 12 bits. */
#define RPMI_TEE_BLOCK_PAGE_COUNT(low) (((low) & (RPMI_TEE_PAGE_SIZE - 1)) + 1)

/* Combine BLOCK_HIGH and BLOCK_LOW, excluding the encoded page count. */
#define RPMI_TEE_BLOCK_ADDRESS(high, low) \
	(((uint64_t)(high) << 32) | ((low) & ~(RPMI_TEE_PAGE_SIZE - 1)))

/* Expand LOW/HIGH block pairs into bounded, representable 4 KiB pages. */
static TEE_Result decode_blocks(const uint32_t *blocks, size_t len,
				uint32_t count, paddr_t *pages, size_t total,
				size_t *next)
{
	uint32_t i = 0;

	if (!count || len % (2 * sizeof(uint32_t)) ||
	    count != len / (2 * sizeof(uint32_t)))
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < count; i++) {
		uint32_t low = TEE_U32_FROM_LITTLE_ENDIAN(blocks[2 * i]);
		uint32_t high = TEE_U32_FROM_LITTLE_ENDIAN(blocks[2 * i + 1]);
		uint64_t address = RPMI_TEE_BLOCK_ADDRESS(high, low);
		uint32_t n = RPMI_TEE_BLOCK_PAGE_COUNT(low);
		uint64_t last = 0;

		/* The block must fit within the parcel's remaining pages. */
		if (n > total - *next)
			return TEE_ERROR_BAD_FORMAT;

		if (ADD_OVERFLOW(address,
				 ((uint64_t)n << RPMI_TEE_PAGE_SHIFT) - 1,
				 &last))
			return TEE_ERROR_BAD_FORMAT;

		if ((paddr_t)last != last)
			return TEE_ERROR_BAD_FORMAT;

		while (n--) {
			pages[(*next)++] = address;
			address += RPMI_TEE_PAGE_SIZE;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result rpmi_tee_memory_accept(struct mbox_chan *channel,
				  struct rpmi_tee_memory_accept_args *args)
{
	struct rpmi_tee_memory_accept_req req = {};
	struct rpmi_tee_memory_accept_resp *resp = NULL;
	struct rpmi_tee_memory_accept_memory_req memory = {};
	uint32_t max_msg_data_size = 0;
	size_t max_resp_len = 0;
	size_t resp_len = 0;
	size_t total = 0;
	size_t next = 0;
	uint32_t returned = 0;
	uint32_t remaining = 0;
	uint32_t block_index = 0;
	uint32_t block_count = 0;
	int32_t status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	if (!channel || !args)
		return TEE_ERROR_BAD_PARAMETERS;

	args->page_count = 0;
	args->needs_release = false;
	if (!args->pages || !args->page_count_max ||
	    args->page_count_max > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	res = rpmi_mbox_get_attribute(channel, RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE,
				      &max_msg_data_size);
	if (res)
		return res;

	max_resp_len = max_msg_data_size;
	/* The channel must fit the request and a response with one block. */
	if (max_resp_len < sizeof(*resp) + 2 * sizeof(uint32_t) ||
	    max_msg_data_size < sizeof(req))
		return TEE_ERROR_NOT_SUPPORTED;

	resp = malloc(max_resp_len);
	if (!resp)
		return TEE_ERROR_OUT_OF_MEMORY;

	req.acceptor_id = TEE_U32_TO_LITTLE_ENDIAN(args->acceptor_id);
	req.access = TEE_U32_TO_LITTLE_ENDIAN(args->access);
	req.parcel_id = TEE_U32_TO_LITTLE_ENDIAN(args->parcel_id);
	req.nonce = TEE_U32_TO_LITTLE_ENDIAN(args->nonce);
	req.creator_id = TEE_U32_TO_LITTLE_ENDIAN(args->creator_id);
	req.creator_access = TEE_U32_TO_LITTLE_ENDIAN(args->creator_access);
	req.max_pages = TEE_U32_TO_LITTLE_ENDIAN(args->page_count_max);
	resp_len = max_resp_len;
	/* A failed exchange may still have acquired interest in firmware. */
	args->needs_release = true;
	res = tee_send_with_status(channel, RPMI_TEE_MEMORY_PARCEL_ACCEPT,
				   &req, sizeof(req), resp, &resp_len, &status);
	if (res)
		goto out;
	res = rpmi_status_to_tee_result(status);
	if (res) {
		/* An explicit rejection did not acquire receiver interest. */
		args->needs_release = false;
		goto out;
	}
	if (resp_len < sizeof(*resp)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	total = TEE_U32_FROM_LITTLE_ENDIAN(resp->page_count);
	returned = TEE_U32_FROM_LITTLE_ENDIAN(resp->returned);
	remaining = TEE_U32_FROM_LITTLE_ENDIAN(resp->remaining);
	if (!total || total > args->page_count_max || returned > total ||
	    remaining > total - returned) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	block_count = returned + remaining;

	/* Expand this response's blocks into physical page addresses. */
	res = decode_blocks(resp->blocks, resp_len - sizeof(*resp), returned,
			    args->pages, total, &next);
	if (res)
		goto out;
	block_index = returned;

	memory.parcel_id = TEE_U32_TO_LITTLE_ENDIAN(args->parcel_id);
	while (remaining) {
		struct rpmi_tee_memory_accept_memory_resp *part = (void *)resp;

		/* Every remaining block must contribute at least one page. */
		if (next == total) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		memory.start_index = TEE_U32_TO_LITTLE_ENDIAN(block_index);
		resp_len = max_resp_len;
		res = tee_send_with_status(channel,
					   RPMI_TEE_MEMORY_PARCEL_ACCEPT_MEMORY,
					   &memory, sizeof(memory), part,
					   &resp_len, &status);
		if (res)
			goto out;
		res = rpmi_status_to_tee_result(status);
		if (res) {
			/* Firmware has aborted the incomplete acceptance. */
			args->needs_release = false;
			goto out;
		}
		if (resp_len < sizeof(*part)) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		returned = TEE_U32_FROM_LITTLE_ENDIAN(part->returned);
		remaining = TEE_U32_FROM_LITTLE_ENDIAN(part->remaining);
		if (returned > block_count - block_index ||
		    remaining != block_count - block_index - returned) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}
		res = decode_blocks(part->blocks, resp_len - sizeof(*part),
				    returned, args->pages, total, &next);
		if (res)
			goto out;
		block_index += returned;
	}

	if (next != total)
		res = TEE_ERROR_BAD_FORMAT;
	else
		args->page_count = total;

out:
	free(resp);
	return res;
}

TEE_Result rpmi_tee_memory_release(struct mbox_chan *channel,
				   uint32_t ep_id, uint32_t parcel_id)
{
	struct rpmi_tee_memory_release_req req = {};
	uint32_t resp = 0;
	size_t resp_len = sizeof(resp);
	int32_t status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	if (!channel)
		return TEE_ERROR_BAD_PARAMETERS;

	req.parcel_id = TEE_U32_TO_LITTLE_ENDIAN(parcel_id);
	req.ep_count = TEE_U32_TO_LITTLE_ENDIAN(1);
	req.ep_id = TEE_U32_TO_LITTLE_ENDIAN(ep_id);
	res = tee_send_with_status(channel, RPMI_TEE_MEMORY_PARCEL_RELEASE,
				   &req, sizeof(req), &resp, &resp_len,
				   &status);
	if (res)
		return res;
	if (resp_len != sizeof(resp))
		return TEE_ERROR_BAD_FORMAT;

	return rpmi_status_to_tee_result(status);
}

/* Signals. */

struct rpmi_tee_signal_bus_setup_req {
	uint32_t sender_id;
	uint32_t target_id;
	uint32_t bus_width;
	uint32_t sender_signals;
} __packed;

struct rpmi_tee_signal_bus_teardown_req {
	uint32_t sender_id;
	uint32_t target_id;
} __packed;

struct rpmi_tee_signal_raise_req {
	uint32_t target_id;
	uint32_t signal_count;
	uint32_t signal;
};

TEE_Result rpmi_tee_signal_bus_setup_get_args(const void *request,
					      size_t request_len,
					      uint32_t *sender_id,
					      uint32_t *target_id,
					      uint32_t *bus_width,
					      uint32_t *sender_signals)
{
	const struct rpmi_tee_signal_bus_setup_req *req = request;

	if (request_len != sizeof(*req))
		return TEE_ERROR_BAD_FORMAT;

	*sender_id = get_unaligned_le32(&req->sender_id);
	*target_id = get_unaligned_le32(&req->target_id);
	*bus_width = get_unaligned_le32(&req->bus_width);
	*sender_signals = get_unaligned_le32(&req->sender_signals);

	return TEE_SUCCESS;
}

TEE_Result rpmi_tee_signal_bus_teardown_get_args(const void *request,
						 size_t request_len,
						 uint32_t *sender_id,
						 uint32_t *target_id)
{
	const struct rpmi_tee_signal_bus_teardown_req *req = request;

	if (request_len != sizeof(*req))
		return TEE_ERROR_BAD_FORMAT;

	*sender_id = get_unaligned_le32(&req->sender_id);
	*target_id = get_unaligned_le32(&req->target_id);

	return TEE_SUCCESS;
}

TEE_Result rpmi_tee_signal_raise(struct mbox_chan *channel,
				 uint32_t target_id, uint32_t signal_id,
				 int32_t *status)
{
	struct rpmi_tee_signal_raise_req req = {};
	uint32_t resp = 0;
	size_t resp_len = sizeof(resp);
	int32_t service_status = RPMI_ERR_FAILED;
	TEE_Result res = TEE_SUCCESS;

	if (!channel)
		return TEE_ERROR_BAD_PARAMETERS;

	req.target_id = TEE_U32_TO_LITTLE_ENDIAN(target_id);
	req.signal_count = TEE_U32_TO_LITTLE_ENDIAN(1); /* Only one signal. */
	req.signal = TEE_U32_TO_LITTLE_ENDIAN(signal_id);
	res = tee_send_with_status(channel, RPMI_TEE_SIGNAL_RAISE, &req,
				   sizeof(req), &resp, &resp_len,
				   &service_status);
	if (res)
		return res;
	if (resp_len != sizeof(resp))
		return TEE_ERROR_BAD_FORMAT;

	*status = service_status;

	return TEE_SUCCESS;
}
