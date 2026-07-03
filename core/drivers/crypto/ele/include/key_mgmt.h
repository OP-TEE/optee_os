/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 NXP
 */
#ifndef __KEY_MGMT_H__
#define __KEY_MGMT_H__

#include <tee_api_types.h>

/* Plain-text key flag for key generation and signature commands */
#define IMX_ELE_FLAG_PLAINTEXT_KEY	0x8

/* ECC key types */
#define ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1	0x7112
#define ELE_KEY_TYPE_ECC_PUB_KEY_SECP_R1	0x4112

/*
 * Generate a plain-text asymmetric key pair via EdgeLock Enclave.
 *
 * For plain key generation the key management handle, key group, key
 * lifetime, key usage, permitted algorithm, monotonic-counter-increment
 * and sync flags are not used by ELE and must be passed as zero / false.
 *
 * @priv_key_buf:    caller-allocated buffer that receives the private key
 * @priv_key_size:   size in bytes of @priv_key_buf
 * @public_key_buf:  caller-allocated buffer that receives the public key
 *                   (x || y coordinates, each @key_size_bits/8 bytes)
 * @public_key_size: size in bytes of @public_key_buf
 * @key_type:        ELE key type (e.g. ELE_KEY_TYPE_ECC_KEY_PAIR_SECP_R1)
 * @key_size_bits:   key security size in bits (224, 256, 384 or 521)
 */
TEE_Result imx_ele_generate_keypair(uint8_t *priv_key_buf,
				    size_t priv_key_size,
				    uint8_t *public_key_buf,
				    size_t public_key_size,
				    uint16_t key_type,
				    size_t key_size_bits);

#endif /* __KEY_MGMT_H__ */
