/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __TMEL_KM_CLIENT_H
#define __TMEL_KM_CLIENT_H

#include <stdint.h>
#include <tee_api_types.h>
#include <tmel_com_client.h>

#define TME_KDF_SW_CONTEXT_BYTES_MAX	128
#define TME_KDF_SALT_LABEL_BYTES_MAX	64

/*
 * Key handles are opaque 32-bit tokens returned by TME-Lite. These sentinel
 * values are never returned as valid handles.
 */
#define TME_KEY_HANDLE_INVALID		0xFFFFFFFF
#define TME_KEY_HANDLE_ALLOC		0xAAAAAAAA

#define TME_KID_CHIP_RAND_BASE		9
#define TME_KID_L2_KEYWRAPSVC		6

#define TME_KD_ICE_ENDPOINT		0x80
#define TME_KD_TCSR_ENDPOINT		0x100

/*
 * struct tme_key_policy - Policy of a derived key
 * @low:  key type, purpose, usage, source, owner, lineage, length and
 *        algorithm fields
 * @high: policy version, authority and destination fields
 */
struct tme_key_policy {
	uint32_t low;
	uint32_t high;
};

#define TME_KSC_SOC_SEC_BOOT_STATE	0x00000002
#define TME_KSC_SOC_DEBUG_STATE		0x00000004
#define TME_KSC_TME_LIFECYCLE_STATE	0x00000008
#define TME_KSC_SW_CONTEXT		0x00000020
#define TME_KSC_CHILD_KEY_POLICY	0x00000040

#define TME_KAL_KDF_NIST		0x80000
#define TME_KAL_SHA512_HMAC		0x58000

#define TME_KT_SYMMETRIC		0x00
#define TME_KL_128			(0x01 << 3)
#define TME_KL_256			(0x04 << 3)
#define TME_KP_GENERIC			(0x00 << 7)
#define TME_KOP_ENCRYPTION		(0x01 << 10)
#define TME_KOP_DECRYPTION		(0x02 << 10)
#define TME_KSL_HW_KEY			(0x02 << 20)
#define TME_KO_TZ			(0x02 << 26)
#define TME_KLI_NP_CU			(0x01 << 30)

#define TME_KPV_VERSION			(0x04 << 12)
#define TME_KAU_TZ			(0x01 << 18)

#define TME_KAL_AES128_ECB		(0x00 << 14)
#define TME_KAL_AES256_ECB		(0x01 << 14)

#define TME_CRED_SLOT_ID_NONE		0

/*
 * struct tme_kdf_spec - Description of a key derivation
 * @kdf_algo:         KDF algorithm, TME_KAL_KDF_NIST
 * @input_key:        ID of the key the new key is derived from, TME_KID_*
 * @mix_key:          ID of a key to mix in; not used by this driver
 * @l2_key:           ID of the level 2 key, TME_KID_L2_*
 * @policy:           policy of the derived key
 * @sw_context:       software context input
 * @sw_context_len:   valid bytes in @sw_context
 * @security_context: device state bound into the key, TME_KSC_* flags
 * @salt_label:       salt and label input
 * @salt_label_len:   valid bytes in @salt_label
 * @prf_digest_algo:  digest algorithm of the PRF, TME_KAL_SHA512_HMAC
 */
struct tme_kdf_spec {
	uint32_t kdf_algo;
	uint32_t input_key;
	uint32_t mix_key;
	uint32_t l2_key;
	struct tme_key_policy policy;
	uint8_t sw_context[TME_KDF_SW_CONTEXT_BYTES_MAX];
	uint32_t sw_context_len;
	uint32_t security_context;
	uint8_t salt_label[TME_KDF_SALT_LABEL_BYTES_MAX];
	uint32_t salt_label_len;
	uint32_t prf_digest_algo;
};

/*
 * struct tmel_km_derive_key_msg - Message to derive a key
 * @input.key_id:        TME_KEY_HANDLE_ALLOC, to get a new handle
 * @input.kdf_info:      physical address of a struct tme_kdf_spec
 * @input.kdf_info_len:  size of that struct in bytes
 * @input.cred_slot:     credential slot, TME_CRED_SLOT_ID_NONE
 * @output.key_id:       handle of the derived key
 * @output.status:       TME_STATUS_* result
 * @output.seq_status:   sequencer error status
 */
struct tmel_km_derive_key_msg {
	struct {
		uint32_t key_id;
		uint32_t kdf_info;
		uint32_t kdf_info_len;
		uint32_t cred_slot;
	} input;
	struct {
		uint32_t key_id;
		uint32_t status;
		struct tme_sequencer_status seq_status;
	} output;
};

/*
 * struct tmel_km_distribute_key_msg - Message to send a key to a destination
 * @input.key_id:      handle of the key
 * @input.dst_id:      destination, TME_KD_*
 * @input.dst_idx:     key slot index at the destination
 * @output.status:     TME_STATUS_* result
 * @output.seq_status: sequencer error status
 */
struct tmel_km_distribute_key_msg {
	struct {
		uint32_t key_id;
		uint32_t dst_id;
		uint32_t dst_idx;
	} input;
	struct {
		uint32_t status;
		struct tme_sequencer_status seq_status;
	} output;
};

/*
 * struct tmel_km_clear_key_msg - Message to free a key handle
 * @input.key_id:      handle of the key
 * @output.status:     TME_STATUS_* result
 * @output.seq_status: sequencer error status
 */
struct tmel_km_clear_key_msg {
	struct {
		uint32_t key_id;
	} input;
	struct {
		uint32_t status;
		struct tme_sequencer_status seq_status;
	} output;
};

/*
 * tmel_km_derive_key() - Derive a key inside TME-Lite
 * @kdf_spec:   description of the derivation
 * @key_handle: set to the handle of the new key
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @kdf_spec or @key_handle is NULL.
 *   TEE_ERROR_BAD_STATE      the TME-Lite session is not up.
 *   other                    tmel_com_client_send_message() error, or TME-Lite
 *                            failed the request.
 */
TEE_Result tmel_km_derive_key(const struct tme_kdf_spec *kdf_spec,
			      uint32_t *key_handle);

/*
 * tmel_km_distribute_key() - Send a derived key to a destination
 * @key_handle: handle from tmel_km_derive_key()
 * @dst_id:     destination, TME_KD_*
 * @dst_idx:    key slot index at the destination
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @key_handle is TME_KEY_HANDLE_INVALID.
 *   other                    tmel_com_client_send_message() error, or TME-Lite
 *                            failed the request.
 */
TEE_Result tmel_km_distribute_key(uint32_t key_handle,
				  uint32_t dst_id,
				  uint32_t dst_idx);

/*
 * tmel_km_clear_key() - Free a key handle inside TME-Lite
 * @key_handle: handle from tmel_km_derive_key()
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @key_handle is TME_KEY_HANDLE_INVALID.
 *   other                    tmel_com_client_send_message() error, or TME-Lite
 *                            failed the request.
 */
TEE_Result tmel_km_clear_key(uint32_t key_handle);

/*
 * tmel_km_read_tcsr_key_and_clear() - Read a distributed key from the TCSR
 * @key:      buffer for the key
 * @key_size: size of @key in bytes
 * @slot_id:  0 for the primary key registers, 1 for the secondary ones
 *
 * The registers are cleared after the read. If that fails, @key is zeroed.
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @key is NULL or @slot_id is above 1.
 *   TEE_ERROR_SHORT_BUFFER   @key_size is smaller than the register block.
 *   TEE_ERROR_GENERIC        the registers are not mapped.
 *   TEE_ERROR_SECURITY       a register did not clear.
 */
TEE_Result tmel_km_read_tcsr_key_and_clear(uint32_t *key, uint32_t key_size,
					   uint32_t slot_id);

/*
 * tmel_km_create_key_policy() - Build the policy of a symmetric HW key
 * @key_length:      key size in bits, 128 or 256
 * @algo_mode:       TME_KAL_AES* mode
 * @key_destination: TME_KD_*
 * @lineage:         TME_KLI_*
 * @policy:          set to the policy
 *
 * Returns:
 *   TEE_ERROR_BAD_PARAMETERS @policy is NULL or @key_length is not 128 or 256.
 */
TEE_Result tmel_km_create_key_policy(uint32_t key_length,
				     uint32_t algo_mode,
				     uint32_t key_destination,
				     uint32_t lineage,
				     struct tme_key_policy *policy);

#endif /* __TMEL_KM_CLIENT_H */
