/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
