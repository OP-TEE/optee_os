// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#include <pta_socket.h>
#include <string.h>
#include <tee_internal_api.h>
#include <__tee_tcpsocket_defines.h>
#include <__tee_udpsocket_defines.h>

#include "tee_socket_private.h"

static TEE_Result invoke_socket_pta(uint32_t cmd_id, uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	static TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	static const TEE_UUID socket_uuid = PTA_SOCKET_UUID;

	if (sess == TEE_HANDLE_NULL) {
		TEE_Result res = TEE_OpenTASession(&socket_uuid,
						   TEE_TIMEOUT_INFINITE,
						   0, NULL, &sess, NULL);

		if (res != TEE_SUCCESS)
			return res;
	}

	return TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, cmd_id,
				   param_types, params, NULL);
}

TEE_Result __tee_socket_pta_open(TEE_ipSocket_ipVersion ip_vers,
				 const char *addr, uint16_t port,
				 uint32_t protocol, uint32_t *handle)
{
	TEE_Result res;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_VALUE_OUTPUT);
	memset(params, 0, sizeof(params));

	switch (ip_vers) {
	case TEE_IP_VERSION_DC:
	case TEE_IP_VERSION_4:
	case TEE_IP_VERSION_6:
		params[0].value.a = ip_vers;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	params[0].value.b = port;

	if (!addr)
		return TEE_ERROR_BAD_PARAMETERS;
	params[1].memref.buffer = (void *)addr;
	params[1].memref.size = strlen(addr) + 1;

	switch (protocol) {
	case TEE_ISOCKET_PROTOCOLID_TCP:
	case TEE_ISOCKET_PROTOCOLID_UDP:
		params[2].value.a = protocol;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = invoke_socket_pta(PTA_SOCKET_OPEN, param_types, params);
	if (res == TEE_SUCCESS)
		*handle = params[3].value.a;
	return res;
}

TEE_Result __tee_socket_pta_close(uint32_t handle)
{
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));

	params[0].value.a = handle;
	return invoke_socket_pta(PTA_SOCKET_CLOSE, param_types, params);
}

TEE_Result __tee_socket_pta_send(uint32_t handle, const void *buf,
				 uint32_t *len, uint32_t timeout)
{
	TEE_Result res;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_MEMREF_INPUT,
				      TEE_PARAM_TYPE_VALUE_OUTPUT,
				      TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));

	params[0].value.a = handle;
	params[0].value.b = timeout;

	params[1].memref.buffer = (void *)buf;
	params[1].memref.size = *len;

	res = invoke_socket_pta(PTA_SOCKET_SEND, param_types, params);
	*len = params[2].value.a;
	return res;
}

TEE_Result __tee_socket_pta_recv(uint32_t handle, void *buf, uint32_t *len,
				 uint32_t timeout)

{
	TEE_Result res;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_MEMREF_OUTPUT,
				      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));

	params[0].value.a = handle;
	params[0].value.b = timeout;

	params[1].memref.buffer = buf;
	params[1].memref.size = *len;

	res = invoke_socket_pta(PTA_SOCKET_RECV, param_types, params);
	*len =  params[1].memref.size;
	return res;
}

TEE_Result __tee_socket_pta_ioctl(uint32_t handle, uint32_t command, void *buf,
				  uint32_t *len)
{
	TEE_Result res;
	uint32_t param_types;
	TEE_Param params[TEE_NUM_PARAMS];

	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				      TEE_PARAM_TYPE_MEMREF_INOUT,
				      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	memset(params, 0, sizeof(params));

	params[0].value.a = handle;
	params[0].value.b = command;

	params[1].memref.buffer = buf;
	params[1].memref.size = *len;

	res = invoke_socket_pta(PTA_SOCKET_IOCTL, param_types, params);
	*len =  params[1].memref.size;
	return res;
}
