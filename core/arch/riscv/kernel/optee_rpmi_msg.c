// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <io.h>
#include <kernel/notif.h>
#include <kernel/thread.h>
#include <optee_rpmi.h>
#include <rpmi_tee.h>
#include <string.h>
#include <utee_defines.h>

#include "optee_rpmi_private.h"

/* Matching Linux's OPTEE_RPMI_SERVICE_UUID. */
static const uint8_t service_uuid[] = {
	0x48, 0x61, 0x78, 0xe0, 0xe7, 0xf8, 0x11, 0xe3,
	0xbc, 0x5e, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b,
};

/* Decoded view of a normal RPMI request; data borrows the input buffer. */
struct rpmi_request {
	uint16_t servicegroup_id;
	uint8_t service_id;
	const void *data;
	size_t len;
};

/* Retire a parcel identified by an unaligned control request. */
static TEE_Result handle_unregister_shm(uint32_t caller,
					const void *service_data,
					size_t service_len)
{
	const struct optee_rpmi_unregister_req *req = service_data;
	uint64_t global_id = 0;

	if (service_len != sizeof(*req))
		return TEE_ERROR_BAD_PARAMETERS;

	global_id = get_unaligned_le64(&req->global_id);

	return rpmi_shm_unregister(optee_rpmi_shm_context(),
				   optee_rpmi_channel(), caller,
				   global_id);
}

/* Dispatch an OP-TEE service request and prepare its service response. */
static TEE_Result
dispatch_optee_request(uint32_t caller, const void *service_data,
		       size_t service_len,
		       union optee_rpmi_control_response *resp,
		       size_t *response_len)
{
	size_t size = sizeof(resp->status);
	TEE_Result status = TEE_SUCCESS;
	uint32_t op = 0;

	if (*response_len < sizeof(*resp))
		return TEE_ERROR_SHORT_BUFFER;
	/* The operation field is also the size of optee_rpmi_probe_req. */
	if (service_len < sizeof(op)) {
		status = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	op = get_unaligned_le32(service_data);
	switch (op) {
	case OPTEE_RPMI_GET_API_VERSION:
		size = sizeof(resp->api);
		resp->api.major =
			TEE_U32_TO_LITTLE_ENDIAN(OPTEE_RPMI_VERSION_MAJOR);
		resp->api.minor =
			TEE_U32_TO_LITTLE_ENDIAN(OPTEE_RPMI_VERSION_MINOR);
		break;
	case OPTEE_RPMI_GET_OS_VERSION:
		size = sizeof(resp->os);
		resp->os.major =
			TEE_U32_TO_LITTLE_ENDIAN(CFG_OPTEE_REVISION_MAJOR);
		resp->os.minor =
			TEE_U32_TO_LITTLE_ENDIAN(CFG_OPTEE_REVISION_MINOR);
		break;
	case OPTEE_RPMI_EXCHANGE_CAPABILITIES:
		size = sizeof(resp->caps);
		resp->caps.rpc_param_count =
			TEE_U32_TO_LITTLE_ENDIAN(THREAD_RPC_MAX_NUM_PARAMS);
		resp->caps.max_notification_key =
			TEE_U32_TO_LITTLE_ENDIAN(NOTIF_VALUE_MAX);
		break;
	case OPTEE_RPMI_YIELDING_CALL_WITH_ARG:
	case OPTEE_RPMI_YIELDING_CALL_RESUME:
		size = sizeof(resp->call);
		/* Successful thread start or resume does not return here. */
		status = thread_rpmi_handle_control(caller, op, service_data,
						    service_len);
		break;
	case OPTEE_RPMI_UNREGISTER_SHM:
		status = handle_unregister_shm(caller, service_data,
					       service_len);
		break;
	default:
		status = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

out:
	resp->status_code = TEE_U32_TO_LITTLE_ENDIAN(status);
	*response_len = size;

	return TEE_SUCCESS;
}

/* Validate a complete RPMI packet from REQFWD and return a decoded view. */
static TEE_Result rpmi_parse_request(const void *data, size_t len,
				     struct rpmi_request *request)
{
	const struct rpmi_message *msg = data;
	uint16_t datalen = 0;

	*request = (struct rpmi_request){};
	/* An RPMI message must contain at least its 8-byte header. */
	if (len < sizeof(msg->header))
		return TEE_ERROR_BAD_FORMAT;

	datalen = get_unaligned_le16(&msg->header.datalen);
	/* Bit 3 belongs to the transport; the remaining flags describe type. */
	if ((msg->header.flags & ~BIT(3)) != RPMI_MSG_NORMAL_REQUEST ||
	    datalen % sizeof(uint32_t) ||
	    datalen != len - sizeof(msg->header))
		return TEE_ERROR_BAD_FORMAT;

	request->servicegroup_id =
		get_unaligned_le16(&msg->header.servicegroup_id);
	request->service_id = msg->header.service_id;
	request->data = msg->data;
	request->len = datalen;

	return TEE_SUCCESS;
}

/* Dispatch a forwarded request; the request loop panics on a returned error. */
TEE_Result optee_rpmi_dispatch(uint32_t self_id, const void *data,
			       size_t data_len, void *response,
			       size_t *response_len)
{
	union optee_rpmi_control_response control = {};
	struct rpmi_request request = {};
	const void *service_data = NULL;
	const uint8_t *service = NULL;
	size_t service_len = 0;
	size_t control_len = sizeof(control);
	uint32_t sender_id = 0;
	uint32_t target_id = 0;
	int32_t status = RPMI_ERR_INVALID_PARAM;
	TEE_Result res = TEE_SUCCESS;

	/* Every response needs room for at least the RPMI status word. */
	if (*response_len < sizeof(status))
		return TEE_ERROR_SHORT_BUFFER;

	res = rpmi_parse_request(data, data_len, &request);
	if (res)
		goto out;

	if (request.servicegroup_id != RPMI_TEE_SERVICEGROUP_ID) {
		status = RPMI_ERR_NOTSUPP;
		goto out;
	}

	switch (request.service_id) {
	case RPMI_TEE_CALL:
		res = rpmi_tee_call_get_args(request.data, request.len,
					     &sender_id, &target_id, &service,
					     &service_data, &service_len);
		if (res || target_id != self_id ||
		    memcmp(service, service_uuid, sizeof(service_uuid)))
			/* Pass RPMI_ERR_INVALID_PARAM as status. */
			return rpmi_tee_call_set_response(status, NULL, 0,
						  response, response_len);

		/* Reserve room before an operation can change state. */
		if (*response_len < RPMI_TEE_CALL_RESP_HEADER_SIZE +
				    sizeof(control))
			return TEE_ERROR_SHORT_BUFFER;

		res = dispatch_optee_request(sender_id, service_data,
					     service_len, &control,
					     &control_len);
		if (res)
			return res;

		return rpmi_tee_call_set_response(RPMI_SUCCESS, &control,
						  control_len, response,
						  response_len);
	default:
		status = RPMI_ERR_NOTSUPP;
		break;
	}

out:
	put_unaligned_le32(response, status);
	*response_len = sizeof(status);

	return TEE_SUCCESS;
}
