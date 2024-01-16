/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __DRIVERS_CAAM_EXTENSION_H__
#define __DRIVERS_CAAM_EXTENSION_H__

#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <types_ext.h>

#ifdef CFG_NXP_CAAM_MP_DRV
/*
 * Export the MPMR content.
 * We assume that it is filled with message given in parameter.
 * It contains 32 registers of 8 bits (32 bytes).
 *
 * @mpmr  [out] MPMR buffer read
 * @size  [in/out] MPMR buffer size exported
 */
TEE_Result caam_mp_export_mpmr(uint8_t *mpmr, size_t *size);

/*
 * Export the Manufacturing Protection Public Key.
 *
 * @pubkey [out] Public key read
 * @size   [in/out] Public key size exported
 */
TEE_Result caam_mp_export_publickey(uint8_t *pubkey, size_t *size);

/*
 * MPSign function.
 * This function takes the value in the MPMR if it exists
 * and concatenates any additional data (certificate).
 * The signature over the message is done with the private key.
 *
 * @data	[in] Data to sign
 * @data_size	[in] Data size to sign
 * @sig		[out] Signature
 * @sig_size	[in/out] Signature size
 */
TEE_Result caam_mp_sign(uint8_t *data, size_t *data_size, uint8_t *sig,
			size_t *sig_size);
#endif /* CFG_NXP_CAAM_MP_DRV */

#ifdef CFG_NXP_CAAM_DEK_DRV
/*
 * Data encryption key generation using CAAM Secure Memory.
 *
 * @blob_data  [in/out] Blob data
 */
TEE_Result caam_dek_generate(const uint8_t *payload, size_t payload_size,
			     uint8_t *dek, size_t dek_size);
#endif /* CFG_NXP_CAAM_DEK_DRV */
#endif /* __DRIVERS_CAAM_EXTENSION_H__ */
