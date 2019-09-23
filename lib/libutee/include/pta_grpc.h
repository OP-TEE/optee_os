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
 * The GRPC PTA accepts 32-bit commands whose bits are interpreted as follows:
 * 
 * | xxxx | xxxx xxxx xxxx xxxx xxxx xxxx xxxx |
 *  CMD ID             FUNC ID
 * 
 * The CMD ID part is interpreted by the GRPC PTA. If the CMD ID is 0x1, this
 * indicates that the caller wishes to send a generic RPC request to its host
 * application. The FUNC ID indicates the function ID that the host application
 * knows how to interpret and handle.
 * 
 * For example, if the GRPC PTA receives the following bitmap as its command:
 * 
 * | 0001 | 0000 0000 0000 0000 0000 0000 0011 |
 * 
 * This means "send a generic RPC request to my host application with function
 * ID 3."
 * 
 * The reason for using 0x1 is that the entire value is passed to the REE. When
 * the REE sees an RPC request, if can determine that it is a generic RPC
 * request by examining the upper four bits while the bottom ones are used for
 * data transfer. This way, it is not necessary to reserve one of the four
 * TEE_Param structs to pass the host function ID.
 * 
 * In the future, if the GRPC PTA must perform other tasks, the upper four bits
 * can be used to indicate which of these other tasks to execute.
 */

/* Reserve the upper four bits */
#define PTA_GRPC_CMD_ID_MASK 		0xF0000000
#define PTA_GRPC_CMD_ID_SHIFT		(32 - 4)

/*
 * Send a generic RPC to the host application of the calling TA.
 * 
 * The four TEE_Param structs are marshalled to the REE as requested by the
 * caller. That is, the structs carry no special meaning as far as the GRPC PTA
 * is concerned.
 */
#define PTA_GRPC_EXECUTE		1

/*
 * Verify that the host function ID is not so large that it overlaps with the
 * reserved bits. TA's can use this to assert that their function ID's are OK.
 */
#define PTA_GRPC_IS_FUNC_ID_VALID(func_id) \
	(!((func_id) & PTA_GRPC_CMD_ID_MASK))

/*
 * Create a composite command with the GRPC PTA command ID and the host function
 * ID
 */
#define PTA_GRPC_ENCODE_CMD(cmd, func_id) \
	(((cmd) << PTA_GRPC_CMD_ID_SHIFT) | (func_id))

/* Retrieve the GRPC PTA command ID from a composite command */
#define PTA_GRPC_GET_CMD_ID(cmd)	((cmd) >> PTA_GRPC_CMD_ID_SHIFT)

/* Retrieve the host function ID from a composite command */
#define PTA_GRPC_GET_FUNC_ID(cmd)	((cmd) & ~PTA_GRPC_CMD_ID_MASK)

#endif /* __PTA_GRPC_H */
