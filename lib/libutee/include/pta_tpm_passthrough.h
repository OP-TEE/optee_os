/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#ifndef __PTA_TPM_PASSTHROUGH_H
#define __PTA_TPM_PASSTHROUGH_H

#define PTA_TPM_PASSTHROUGH_UUID { 0x50568cd9, 0x370a, 0x46b8, \
		{ 0x9f, 0x2c, 0x6f, 0xd9, 0x06, 0x64, 0xd2, 0xee } }

/*
 * Submit a raw TPM command to the discrete TPM owned by OP-TEE and return
 * its response. The command/response wire format is plain TPM2 bytes; this
 * PTA is only a transport, identical in shape to the fTPM TA's
 * SUBMIT_COMMAND but backed by the in-core discrete-TPM (SPI TIS) driver.
 *
 * [in]     memref[0]        TPM command buffer
 * [in/out] memref[1]        TPM response buffer (in: capacity, out: length)
 */
#define PTA_TPM_PASSTHROUGH_SUBMIT_COMMAND	0

#endif /* __PTA_TPM_PASSTHROUGH_H */
