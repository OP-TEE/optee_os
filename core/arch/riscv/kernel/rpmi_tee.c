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

/* Memory parcels. */

#define RPMI_TEE_MEMORY_MULTI_SEGMENT	BIT(31)
#define RPMI_TEE_MEMORY_LAST_SEGMENT	BIT(31)

struct rpmi_tee_memory_accept_req {
	uint32_t acceptor_id;
	uint32_t access;
	uint32_t parcel_id;
	uint32_t nonce;
	uint32_t creator_id;
	uint32_t creator_access;
	uint32_t flags;
	uint32_t address_high;
	uint32_t address_low;
	uint32_t max_pages;
	uint32_t other_count;
};

struct rpmi_tee_memory_accept_resp {
	int32_t status;
	uint32_t flags;
	uint32_t page_count;
	uint32_t block_count;
	uint32_t blocks[];
};

struct rpmi_tee_memory_segment_req {
	uint32_t acceptor_id;
	uint32_t parcel_id;
};

struct rpmi_tee_memory_segment_resp {
	int32_t status;
	uint32_t flags;
	uint32_t block_count;
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

/* Expand split HIGH[]/LOW[] arrays into bounded, representable 4 KiB pages. */
static TEE_Result decode_blocks(const uint32_t *blocks, size_t len,
				uint32_t count, paddr_t *pages, size_t total,
				size_t *next)
{
	uint32_t i = 0;

	if (!count || len % (2 * sizeof(uint32_t)) ||
	    count != len / (2 * sizeof(uint32_t)))
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < count; i++) {
		uint32_t high = TEE_U32_FROM_LITTLE_ENDIAN(blocks[i]);
		uint32_t low = TEE_U32_FROM_LITTLE_ENDIAN(blocks[count + i]);
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
	struct rpmi_tee_memory_segment_req segment = {};
	uint32_t max_msg_data_size = 0;
	size_t max_resp_len = 0;
	size_t resp_len = 0;
	size_t total = 0;
	size_t next = 0;
	uint32_t flags = 0;
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

	flags = TEE_U32_FROM_LITTLE_ENDIAN(resp->flags);
	total = TEE_U32_FROM_LITTLE_ENDIAN(resp->page_count);
	if (flags & ~RPMI_TEE_MEMORY_MULTI_SEGMENT || !total ||
	    total > args->page_count_max) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	block_count = TEE_U32_FROM_LITTLE_ENDIAN(resp->block_count);
	/* Expand this response's memory blocks into physical page addresses. */
	res = decode_blocks(resp->blocks, resp_len - sizeof(*resp), block_count,
			    args->pages, total, &next); /* next: page so far. */
	if (res)
		goto out;

	segment.acceptor_id = TEE_U32_TO_LITTLE_ENDIAN(args->acceptor_id);
	segment.parcel_id = TEE_U32_TO_LITTLE_ENDIAN(args->parcel_id);
	while (flags & RPMI_TEE_MEMORY_MULTI_SEGMENT) {
		struct rpmi_tee_memory_segment_resp *part = (void *)resp;

		/* A non-final segment must leave room for another page. */
		if (next == total) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		resp_len = max_resp_len;
		res = tee_send_with_status(channel,
					   RPMI_TEE_MEMORY_SEGMENT_RECEIVE,
					   &segment, sizeof(segment), part,
					   &resp_len, &status);
		if (res)
			goto out;
		res = rpmi_status_to_tee_result(status);
		if (res)
			goto out;
		if (resp_len < sizeof(*part)) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		flags = TEE_U32_FROM_LITTLE_ENDIAN(part->flags);
		if (flags & ~RPMI_TEE_MEMORY_LAST_SEGMENT) {
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		block_count = TEE_U32_FROM_LITTLE_ENDIAN(part->block_count);
		res = decode_blocks(part->blocks, resp_len - sizeof(*part),
				    block_count, args->pages, total, &next);
		if (res)
			goto out;

		flags = flags & RPMI_TEE_MEMORY_LAST_SEGMENT ? 0 :
			RPMI_TEE_MEMORY_MULTI_SEGMENT;
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
