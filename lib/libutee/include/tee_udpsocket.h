/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef __TEE_UDPSOCKET_H
#define __TEE_UDPSOCKET_H

#include <tee_isocket.h>
#include <__tee_ipsocket.h>
#include <__tee_udpsocket_defines.h>

typedef struct TEE_udpSocket_Setup_s {
	TEE_ipSocket_ipVersion ipVersion;
	char *server_addr;
	uint16_t server_port;
} TEE_udpSocket_Setup;

extern TEE_iSocket *const TEE_udpSocket;

#endif /*__TEE_UDPSOCKET_H*/
