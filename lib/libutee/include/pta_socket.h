/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __PTA_SOCKET
#define __PTA_SOCKET

#define PTA_SOCKET_UUID { 0x3b996a7d, 0x2c2b, 0x4a49, { \
			  0xa8, 0x96, 0xe1, 0xfb, 0x57, 0x66, 0xd2, 0xf4 } }

/*
 * [in]		value[0].a	ip version TEE_IP_VERSION_* from tee_ipsocket.h
 * [in]		value[0].b	server port number
 * [in]		memref[1]	server address
 * [in]		value[2].a	protocol, TEE_ISOCKET_PROTOCOLID_*
 * [out]	value[3].a	socket handle
 */
#define PTA_SOCKET_OPEN		1

/*
 * [in]		value[0].a	socket handle
 */
#define PTA_SOCKET_CLOSE	2

#define PTA_SOCKET_TIMEOUT_NONBLOCKING	0
#define PTA_SOCKET_TIMEOUT_BLOCKING	0xffffffff

/*
 * [in]		value[0].a	socket handle
 * [in]		value[0].b	timeout ms or TEE_TIMEOUT_INFINITE
 * [in]		memref[1]	buffer to transmit
 * [out]	value[2].a	number of transmitted bytes
 */
#define PTA_SOCKET_SEND		3

/*
 * [in]		value[0].a	socket handle
 * [in]		value[0].b	timeout ms or TEE_TIMEOUT_INFINITE
 * [out]	memref[1]	buffer
 */
#define PTA_SOCKET_RECV		4

/*
 * [in]		value[0].a	socket handle
 * [in]		value[0].b	ioctl command
 * [in/out]	memref[1]	buffer
 */
#define PTA_SOCKET_IOCTL	5

#endif /*__PTA_SOCKET*/
