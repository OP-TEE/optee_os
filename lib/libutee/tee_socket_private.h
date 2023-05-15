/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef __TEE_SOCKET_PRIVATE_H
#define __TEE_SOCKET_PRIVATE_H

#include <stdint.h>
#include <__tee_ipsocket.h>

static inline uint8_t __tee_socket_ioctl_cmd_to_proto(uint32_t cmd_code)
{
	return cmd_code >> 24;
}

TEE_Result __tee_socket_pta_open(TEE_ipSocket_ipVersion ip_vers,
				 const char *addr, uint16_t port,
				 uint32_t protocol, uint32_t *handle);

TEE_Result __tee_socket_pta_close(uint32_t handle);

TEE_Result __tee_socket_pta_send(uint32_t handle, const void *buf,
				 uint32_t *len, uint32_t timeout);

TEE_Result __tee_socket_pta_recv(uint32_t handle, void *buf, uint32_t *len,
				 uint32_t timeout);

TEE_Result __tee_socket_pta_ioctl(uint32_t handle, uint32_t command, void *buf,
				  uint32_t *len);

#endif /*__TEE_SOCKET_PRIVATE_H*/
