/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 */

#ifndef __TEE_ISOCKET_H
#define __TEE_ISOCKET_H

#include <stdint.h>
#include <tee_api_types.h>
#include <__tee_isocket_defines.h>

typedef void *TEE_iSocketHandle;

typedef const struct TEE_iSocket_s {
	uint32_t TEE_iSocketVersion;
	uint8_t protocolID;
	TEE_Result (*open)(TEE_iSocketHandle *ctx, void *setup,
			   uint32_t *protocolError);

	TEE_Result (*close)(TEE_iSocketHandle ctx);

	TEE_Result (*send)(TEE_iSocketHandle ctx, const void *buf,
			    uint32_t *length, uint32_t timeout);

	TEE_Result (*recv)(TEE_iSocketHandle ctx, void *buf, uint32_t *length,
			   uint32_t timeout);

	uint32_t (*error)(TEE_iSocketHandle ctx);

	TEE_Result (*ioctl)(TEE_iSocketHandle ctx, uint32_t commandCode,
			    void *buf, uint32_t *length);
} TEE_iSocket;

#endif /*__TEE_ISOCKET_H*/
