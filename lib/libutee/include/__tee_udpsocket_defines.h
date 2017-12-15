/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef ____TEE_UDPSOCKET_DEFINES_H
#define ____TEE_UDPSOCKET_DEFINES_H

/* Protocol identifier */
#define TEE_ISOCKET_PROTOCOLID_UDP		0x66

/* Instance specific errors */
#define TEE_ISOCKET_UDP_WARNING_UNKNOWN_OUT_OF_BAND	0xF1020002

/* Instance specific ioctl functions */
#define TEE_UDP_CHANGEADDR			0x66000001
#define TEE_UDP_CHANGEPORT			0x66000002

#endif /*____TEE_UDPSOCKET_DEFINES_H*/
