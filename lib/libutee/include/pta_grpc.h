// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Microsoft Corporation
 */

#ifndef __PTA_GRPC_H
#define __PTA_GRPC_H

/* PTA UUID: {ad0fd0ae-09e1-464b-98ed-0607ec9ebd8b} */
#define PTA_RPC_UUID { 0xad0fd0ae, 0x09e1, 0x464b, { \
		      0x98, 0xed, 0x06, 0x07, 0xec, 0x9e, 0xbd, 0x8b } }

/*
 * Send a Generic RPC request to the host application associated with the 
 * session of the calling TA.
 * 
 * Up to four TEE_Param structs are passed as-is to the REE based on the TA's
 * request.
 */
#define PTA_GRPC_EXECUTE		1

#endif /* __PTA_GRPC_H */
