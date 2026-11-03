/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TFA_COMM_ABI_H
#define __TFA_COMM_ABI_H

/*
 * ABI of the logical partition (LSP) of the EL3 SPMC in TF-A. The reference is
 * lsp_abi.h in plat/qti/wildcat/nord of trusted-firmware-a; change both
 * together.
 *
 *   FFA_MSG_SEND_DIRECT_REQ2 (OP-TEE -> LSP)
 *     w1 = (OP-TEE FF-A ID << 16) | TFA_COMM_LSP_ID
 *     x2, x3 = UUID of the service
 *     x4 = 0
 *     x5 = size of the input buffer in the shared page, 0 if there is none
 *     x6..x17 = arguments, defined by the service
 *
 *   FFA_MSG_SEND_DIRECT_RESP2 (LSP -> OP-TEE)
 *     w1 = (TFA_COMM_LSP_ID << 16) | OP-TEE FF-A ID
 *     x2 = x3 = 0
 *     x4 = status of the LSP (TFA_COMM_LSP_ST_*)
 *     x5 = size of the output buffer that the LSP wrote to the shared page,
 *          0 if it wrote nothing
 *     x6..x17 = results, defined by the service
 *
 * x4 and x5 are reserved for the framing, so the commands of a service and
 * the meaning of the registers x6..x17 are defined by the service itself.
 *
 * The LSP never answers with FFA_ERROR, but the SPMC may.
 */

/* FF-A endpoint ID of the LSP, FFA_LSP_ID in platform_def.h of TF-A */
#define TFA_COMM_LSP_ID			0xC001

/* Status of the LSP (x4 of the response) */
#define TFA_COMM_LSP_ST_SUCCESS		0
#define TFA_COMM_LSP_ST_FAILURE		1	/* the LSP could not do it */
#define TFA_COMM_LSP_ST_INVALID_PARAM	2	/* bad register value or size */
#define TFA_COMM_LSP_ST_NOT_SUPPORTED	3	/* unknown FID, UUID, command */
#define TFA_COMM_LSP_ST_DENIED		4	/* bad origin or sender */

/* Index in the SMC registers of the first argument and result register */
#define TFA_COMM_FIRST_REG		6

#endif /* __TFA_COMM_ABI_H */
