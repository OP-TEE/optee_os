/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019, 2023 NXP
 */
#ifndef PTA_IMX_MANUFACTURING_PROTECTION_H
#define PTA_IMX_MANUFACTURING_PROTECTION_H

#define PTA_MANUFACT_PROTEC_UUID { 0x83268b7c, 0x85e3, 0x11e8, \
		{ 0xad, 0xc0, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc} }

/*
 * Sign the given message with the manufacturing protection private key
 *
 * [in]		memref[0].buffer	Message buffer
 * [in]		memref[0].size		Message size
 * [out]	memref[1].buffer	Signature buffer
 * [out]	memref[1].size		Signature size
 * [out]	memref[2].buffer	MPMR buffer
 * [out]	memref[2].size		MPMR size
 */
#define PTA_IMX_MP_CMD_SIGNATURE_MPMR	0

/*
 * Get the manufacturing protection public key
 *
 * [out]	memref[0].buffer	Public key buffer
 * [out]	memref[0].size		Public key size
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_IMX_MP_CMD_GET_PUBLIC_KEY	1

#endif /* PTA_IMX_MANUFACTURING_PROTECTION_H */
