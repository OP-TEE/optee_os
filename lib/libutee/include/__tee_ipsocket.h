/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef ____TEE_IPSOCKET_H
#define ____TEE_IPSOCKET_H

typedef enum TEE_ipSocket_ipVersion_e {
	TEE_IP_VERSION_DC = 0, /* don’t care */
	TEE_IP_VERSION_4 = 1,
	TEE_IP_VERSION_6 = 2
} TEE_ipSocket_ipVersion;

#endif /*____TEE_IPSOCKET_H*/
