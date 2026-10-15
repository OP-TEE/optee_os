/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc. All Rights Reserved.
 *
 */

#ifndef __ASU_CRYPTO_COMMON_H_
#define __ASU_CRYPTO_COMMON_H_

#include <tee_api_types.h>

/* KeyManager metadata shared by ECC and RSA key-pair generation */
struct asu_km_key_metadata {
	uint16_t key_id;
	uint8_t key_type;
	uint8_t vault_id;
	uint8_t key_use_case;
	uint8_t key_attributes;
	uint16_t length;
	uint32_t epoch_time;
	uint32_t usage_count;
};

/* AES key object used by KeyManager and AES engine requests */
struct asu_aes_key_object {
	uint64_t key_address;
	uint32_t key_size;
	uint32_t key_src;
	uint32_t key_id;
	uint8_t reserved[4];
};

/* KeyManager request params shared by ECC and RSA key-pair generation */
struct asu_km_params {
	struct asu_km_key_metadata key_metadata;
	struct asu_aes_key_object aes_key_obj;
	uint64_t key_object_addr;
	uint64_t key_id_addr;
	uint32_t wrapped_input_len;
	uint32_t key_object_len;
};

/*
 * asu_shadev_acquire() - Claim a SHA engine slot by module ID.
 * @module: ASU_MODULE_SHA2_ID or ASU_MODULE_SHA3_ID
 *
 * Return: TEE_SUCCESS if claimed, TEE_ERROR_NOT_IMPLEMENTED if busy.
 */
TEE_Result asu_shadev_acquire(uint8_t module);

/*
 * asu_shadev_release() - Release a previously claimed SHA engine slot.
 * @module: ASU_MODULE_SHA2_ID or ASU_MODULE_SHA3_ID
 */
void asu_shadev_release(uint8_t module);

#endif /* __ASU_CRYPTO_COMMON_H_ */
