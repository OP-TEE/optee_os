// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#include <pta_socket.h>
#include <tee_internal_api.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>
#include <__tee_tcpsocket_defines_extensions.h>
#include <tee_udpsocket.h>

#include "tee_socket_private.h"

struct socket_ctx {
	uint32_t handle;
	uint32_t proto_error;
};

static TEE_Result tcp_open(TEE_iSocketHandle *ctx, void *setup,
			   uint32_t *proto_error)
{
	TEE_Result res;
	struct socket_ctx *sock_ctx;
	TEE_tcpSocket_Setup *tcp_setup = setup;

	if (!ctx || !setup || !proto_error)
		TEE_Panic(0);

	*proto_error = TEE_SUCCESS;

	sock_ctx = TEE_Malloc(sizeof(*sock_ctx), TEE_MALLOC_FILL_ZERO);
	if (!sock_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = __tee_socket_pta_open(tcp_setup->ipVersion,
				    tcp_setup->server_addr,
				    tcp_setup->server_port,
				    TEE_ISOCKET_PROTOCOLID_TCP,
				    &sock_ctx->handle);
	if (res != TEE_SUCCESS) {
		TEE_Free(sock_ctx);
		sock_ctx = NULL;
	}
	*ctx = (TEE_iSocketHandle)sock_ctx;

	switch (res) {
	case TEE_ISOCKET_ERROR_HOSTNAME:
		*proto_error = res;
		return TEE_ISOCKET_ERROR_PROTOCOL;
	case TEE_ISOCKET_TCP_WARNING_UNKNOWN_OUT_OF_BAND:
		*proto_error = res;
		return TEE_ISOCKET_WARNING_PROTOCOL;
	default:
		return res;
	}
}

static TEE_Result udp_open(TEE_iSocketHandle *ctx, void *setup,
			   uint32_t *proto_error)
{
	TEE_Result res;
	struct socket_ctx *sock_ctx;
	TEE_udpSocket_Setup *udp_setup = setup;

	if (!ctx || !setup || !proto_error)
		TEE_Panic(0);

	*proto_error = TEE_SUCCESS;

	sock_ctx = TEE_Malloc(sizeof(*sock_ctx), TEE_MALLOC_FILL_ZERO);
	if (!sock_ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = __tee_socket_pta_open(udp_setup->ipVersion,
				    udp_setup->server_addr,
				    udp_setup->server_port,
				    TEE_ISOCKET_PROTOCOLID_UDP,
				    &sock_ctx->handle);
	if (res != TEE_SUCCESS) {
		TEE_Free(sock_ctx);
		sock_ctx = NULL;
	}
	*ctx = (TEE_iSocketHandle)sock_ctx;

	switch (res) {
	case TEE_ISOCKET_ERROR_HOSTNAME:
		*proto_error = res;
		return TEE_ISOCKET_ERROR_PROTOCOL;
	case TEE_ISOCKET_UDP_WARNING_UNKNOWN_OUT_OF_BAND:
		*proto_error = res;
		return TEE_ISOCKET_WARNING_PROTOCOL;
	default:
		return res;
	}
}

static TEE_Result sock_close(TEE_iSocketHandle ctx)
{
	TEE_Result res;
	struct socket_ctx *sock_ctx = (struct socket_ctx *)ctx;

	if (ctx == TEE_HANDLE_NULL)
		return TEE_SUCCESS;

	res = __tee_socket_pta_close(sock_ctx->handle);
	TEE_Free(sock_ctx);

	return res;
}

static TEE_Result sock_send(TEE_iSocketHandle ctx, const void *buf,
			   uint32_t *length, uint32_t timeout)
{
	TEE_Result res;
	struct socket_ctx *sock_ctx = (struct socket_ctx *)ctx;

	if (ctx == TEE_HANDLE_NULL || !buf || !length)
		TEE_Panic(0);

	res = __tee_socket_pta_send(sock_ctx->handle, buf, length, timeout);
	sock_ctx->proto_error = res;

	return res;
}

static TEE_Result sock_recv(TEE_iSocketHandle ctx, void *buf, uint32_t *length,
			   uint32_t timeout)
{
	TEE_Result res;
	struct socket_ctx *sock_ctx = (struct socket_ctx *)ctx;

	if (ctx == TEE_HANDLE_NULL || !length || (!buf && *length))
		TEE_Panic(0);

	res = __tee_socket_pta_recv(sock_ctx->handle, buf, length, timeout);
	sock_ctx->proto_error = res;

	return res;
}

static uint32_t sock_error(TEE_iSocketHandle ctx)
{
	struct socket_ctx *sock_ctx = (struct socket_ctx *)ctx;

	if (ctx == TEE_HANDLE_NULL)
		TEE_Panic(0);

	return sock_ctx->proto_error;
}

static TEE_Result tcp_ioctl(TEE_iSocketHandle ctx, uint32_t commandCode,
			    void *buf, uint32_t *length)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct socket_ctx *sock_ctx = (struct socket_ctx *)ctx;

	if (ctx == TEE_HANDLE_NULL || !length || (!buf && *length))
		TEE_Panic(0);

	if  (__tee_socket_ioctl_cmd_to_proto(commandCode) == 0)
		return TEE_SUCCESS;

	switch (commandCode) {
	case TEE_TCP_SET_RECVBUF:
	case TEE_TCP_SET_SENDBUF:
		res = __tee_socket_pta_ioctl(sock_ctx->handle, commandCode,
					     buf, length);
		break;
	default:
		TEE_Panic(0);
	}

	sock_ctx->proto_error = res;

	return res;
}

static TEE_Result udp_ioctl(TEE_iSocketHandle ctx, uint32_t commandCode,
			    void *buf, uint32_t *length)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct socket_ctx *sock_ctx = (struct socket_ctx *)ctx;

	if (ctx == TEE_HANDLE_NULL || !length || (!buf && *length))
		TEE_Panic(0);

	if  (__tee_socket_ioctl_cmd_to_proto(commandCode) == 0)
		return TEE_SUCCESS;

	switch (commandCode) {
	case TEE_UDP_CHANGEADDR:
	case TEE_UDP_CHANGEPORT:
		res = __tee_socket_pta_ioctl(sock_ctx->handle, commandCode,
					     buf, length);
		break;
	default:
		TEE_Panic(0);
	}

	sock_ctx->proto_error = res;

	return res;
}



static TEE_iSocket tcp_socket_instance = {
	.TEE_iSocketVersion = TEE_ISOCKET_VERSION,
	.protocolID = TEE_ISOCKET_PROTOCOLID_TCP,
	.open = tcp_open,
	.close = sock_close,
	.send = sock_send,
	.recv = sock_recv,
	.error = sock_error,
	.ioctl = tcp_ioctl,
};

static TEE_iSocket udp_socket_instance = {
	.TEE_iSocketVersion = TEE_ISOCKET_VERSION,
	.protocolID = TEE_ISOCKET_PROTOCOLID_UDP,
	.open = udp_open,
	.close = sock_close,
	.send = sock_send,
	.recv = sock_recv,
	.error = sock_error,
	.ioctl = udp_ioctl,
};

TEE_iSocket *const TEE_tcpSocket = &tcp_socket_instance;
TEE_iSocket *const TEE_udpSocket = &udp_socket_instance;
