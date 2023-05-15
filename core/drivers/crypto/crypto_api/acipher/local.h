/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Definition of the functions shared locally.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <drvcrypt_acipher.h>

/*
 * Mask Generation function. Use a Hash operation
 * to generate an output @mask from an input @seed
 *
 * @mgf_data  [in/out] MGF data
 */
TEE_Result drvcrypt_rsa_mgf1(struct drvcrypt_rsa_mgf *mgf_data);

/*
 * PKCS#1 - Signature of RSA message and encodes the signature.
 *
 * @ssa_data   [in/out] RSA data to sign / Signature
 */
TEE_Result drvcrypt_rsassa_sign(struct drvcrypt_rsa_ssa *ssa_data);

/*
 * PKCS#1 - Verification the encoded signature of RSA message.
 *
 * @ssa_data   RSA Encoded signature data
 */
TEE_Result drvcrypt_rsassa_verify(struct drvcrypt_rsa_ssa *ssa_data);

#endif /* __LOCAL_H__ */
