/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __SIGN_VERIFY_H__
#define __SIGN_VERIFY_H__

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/* ECDSA signature schemes */
#define ELE_ALGO_ECDSA_SHA224	0x06000608
#define ELE_ALGO_ECDSA_SHA256	0x06000609
#define ELE_ALGO_ECDSA_SHA384	0x0600060A
#define ELE_ALGO_ECDSA_SHA512	0x0600060B

/* Signature generation message type */
#define ELE_SIG_GEN_MSG_TYPE_DIGEST	0x0
#define ELE_SIG_GEN_MSG_TYPE_MESSAGE	0x1

/* Signature verification status codes returned by ELE */
#define ELE_SIG_VERIFICATION_SUCCESS	0x5A3CC3A5
#define ELE_SIG_VERIFICATION_FAILURE	0x2B4DD4B2

/*
 * Generate an ECDSA signature using a plain-text private key.
 *
 * @priv_key:         private key bytes (big-endian scalar)
 * @priv_key_size:    size in bytes of @priv_key
 * @message:          digest or message bytes to sign
 * @message_size:     size in bytes of @message
 * @signature:        caller-allocated output buffer for the signature (r || s)
 * @signature_size:   size in bytes of @signature buffer
 * @signature_scheme: ELE algorithm identifier (e.g. ELE_ALGO_ECDSA_SHA256)
 * @message_type:     ELE_SIG_GEN_MSG_TYPE_DIGEST or
 *		      ELE_SIG_GEN_MSG_TYPE_MESSAGE
 * @key_type:         ELE key type (e.g. ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1)
 * @key_size_bits:    key security size in bits
 */
TEE_Result imx_ele_signature_generate(const uint8_t *priv_key,
				      size_t priv_key_size,
				      const uint8_t *message,
				      size_t message_size,
				      uint8_t *signature,
				      size_t signature_size,
				      uint32_t signature_scheme,
				      uint8_t message_type,
				      uint32_t key_type,
				      size_t key_size_bits);

/*
 * Verify an ECDSA signature using a plain-text public key.
 *
 * @public_key:       public key bytes (x || y coordinates)
 * @public_key_size:  size in bytes of @public_key
 * @message:          digest or message bytes that were signed
 * @message_size:     size in bytes of @message
 * @signature:        signature bytes (r || s) to verify
 * @signature_size:   size in bytes of @signature
 * @key_security_size: key security size in bits
 * @key_type:         ELE key type (e.g. ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1)
 * @signature_scheme: ELE algorithm identifier
 * @message_type:     ELE_SIG_GEN_MSG_TYPE_DIGEST or
 *		      ELE_SIG_GEN_MSG_TYPE_MESSAGE
 */
TEE_Result imx_ele_signature_verify(const uint8_t *public_key,
				    size_t public_key_size,
				    const uint8_t *message,
				    size_t message_size,
				    const uint8_t *signature,
				    size_t signature_size,
				    size_t key_security_size,
				    uint16_t key_type,
				    uint32_t signature_scheme,
				    uint8_t message_type);

#endif /* __SIGN_VERIFY_H__ */
