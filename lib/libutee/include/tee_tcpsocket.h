/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef __TEE_TCPSOCKET_H
#define __TEE_TCPSOCKET_H

#include <tee_isocket.h>
#include <__tee_ipsocket.h>
#include <__tee_tcpsocket_defines.h>

typedef struct TEE_tcpSocket_Setup_s {
	TEE_ipSocket_ipVersion ipVersion;
	char *server_addr;
	uint16_t server_port;
} TEE_tcpSocket_Setup;

extern TEE_iSocket *const TEE_tcpSocket;

#endif /*__TEE_TCPSOCKET_H*/
