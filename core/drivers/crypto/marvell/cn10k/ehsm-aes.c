// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025 Marvell.
 */

#include <stdint.h>

#include "ehsm.h"
#include "ehsm-aes.h"
#include "ehsm-hal.h"
#include "ehsm-security.h"

/**
 * Reset AES engine and zeroize key registers
 *
 * @param       handle		Pointer to EHSM handle
 *
 * @return      SEC_NO_ERROR
 */
enum sec_return ehsm_aes_zeroize(struct ehsm_handle *handle)
{
	struct ehsm_command cmd;
	enum ehsm_status estat;

	ehsm_clear_command(&cmd);

	cmd.opcode = BCM_AES_ZEROIZE;
	estat = ehsm_command(handle, &cmd);
	if (estat != STATUS_SUCCESS)
		return (enum sec_return)estat;

	return SEC_NO_ERROR;
}

/**
 * Generates an AES plaintext key
 *
 * @param       handle          Pointer to EHSM handle
 * @param       key_size_bits   128, 192, or 256
 * @param[in]   key             Key pointer
 *
 * @return      SEC_NO_ERROR
 */
enum sec_return ehsm_aes_key_gen(struct ehsm_handle *handle,
				 enum ehsm_aes_key_size key_size_bits,
				 const void *key)
{
	struct ehsm_command cmd;
	enum ehsm_status estat;

	ehsm_clear_command(&cmd);

	cmd.args[0] = key_size_bits;
	cmd.args[1] = ehsm_addr_low(key);
	cmd.args[2] = ehsm_addr_hi(key);
	cmd.opcode = BCM_AES_KEY_GEN;
	estat = ehsm_command(handle, &cmd);
	if (estat != STATUS_SUCCESS)
		return (enum sec_return)estat;

	return SEC_NO_ERROR;
}

/**
 * Initialize AES engine for non-GCM mode
 *
 * @param       ehsm_handle     Pointer to EHSM handle
 * @param       decrypt         True to decrypt, false to encrypt
 * @param       key_size        Key size, 128, 192, or 256
 * @param       aes_mode        AES encryption mode to use
 * @param       ctr_modular     Used in AES_CTR mode,
 *                              0-15 - use 128 bit counter,
 *                              16-127 - Use specified counter
 * @param       endian_swap     Set true for big-endian mode
 *
 * @return      SEC_NO_ERROR or SEC_INVALID_PARAMETER
 */
enum sec_return ehsm_aes_init(struct ehsm_handle *handle,
			      bool decrypt,
			      enum ehsm_aes_key_size key_size,
			      enum ehsm_aes_mode aes_mode,
			      uint8_t ctr_modular,
			      bool endian_swap)
{
	struct ehsm_command cmd;
	enum ehsm_status estat;

	if (aes_mode == EHSM_AES_MODE_CTR) {
		if (ctr_modular >= 128)
			return SEC_INVALID_PARAMETER;
	} else if (aes_mode == EHSM_AES_MODE_GCM) {
		return SEC_INVALID_PARAMETER;
	} else if (ctr_modular != 0) {
		return SEC_INVALID_PARAMETER;
	}
	if (key_size != (key_size & 0x180))
		return SEC_INVALID_PARAMETER;

	ehsm_clear_command(&cmd);

	cmd.args[0] = decrypt ? 1 : 0;
	cmd.args[1] = key_size;
	cmd.args[2] = aes_mode;
	cmd.args[3] = ctr_modular;
	cmd.args[8] = endian_swap;
	cmd.opcode = BCM_AES_INIT;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

/**
 * Initialize AES engine for GCM mode
 *
 * @param       ehsm_handle     Pointer to EHSM handle
 * @param       decrypt         True to decrypt, false to encrypt
 * @param       aad_size        Additional authentication data size in bytes
 * @param       tag_size        Authenticated tag size [1-16]
 * @param       iv_size         IV size in bytes 0 use 12 bytes from IV
 * @param[in]   iv              Initialization vector
 * @param       endian_swap     Use big endian data
 *
 * @return      SEC_NO_ERROR or STATUS_INVALID_TAG_SIZE
 */
enum sec_return ehsm_aes_gcm_init(struct ehsm_handle *handle,
				  bool decrypt,
				  uint32_t aad_size,
				  uint32_t tag_size,
				  uint32_t iv_size,
				  const uint32_t *iv,
				  bool endian_swap)
{
	struct ehsm_command cmd;
	enum ehsm_status estat;

	ehsm_clear_command(&cmd);

	cmd.args[0] = decrypt ? 1 : 0;
	cmd.args[1] = aad_size;
	if (tag_size < 1 || tag_size > 16)
		return SEC_INVALID_PARAMETER;
	cmd.args[2] = tag_size;
	cmd.args[3] = iv_size;
	cmd.args[4] = iv[0];
	cmd.args[5] = iv[1];
	cmd.args[6] = iv[2];
	cmd.args[7] = endian_swap;
	cmd.opcode = BCM_AES_GCM_INIT;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

/**
 * Load a plaintext key into the EHSM register bank
 *
 * @param       handle          EHSM handle pointer
 * @param       key_size_bits   128, 192, or 256
 * @param[in]   key             Key pointer
 * @param       secondary_key   Load key into secondary registers
 * @param       endian_swap     Set true for big endian
 *
 * @return  SEC_NO_ERROR, STATUS_DISABLED_IN_FIPS_MODE,
 *          STATUS_UNSUPPORTED_PARAMETER, STATUS_NULL_POINTER,
 *          STATUS_DMA_BUFFER_UNALIGNED, STATUS_DATA_BUFFER_UNALIGNED
 */
enum sec_return ehsm_aes_load_key(struct ehsm_handle *handle,
				  enum ehsm_aes_key_size key_size_bits,
				  const void *key,
				  bool secondary_key,
				  bool endian_swap)
{
	struct ehsm_command cmd;
	enum ehsm_status estat;

	ehsm_clear_command(&cmd);

	cmd.args[0] = key_size_bits;
	cmd.args[1] = ehsm_addr_low(key);
	cmd.args[2] = ehsm_addr_hi(key);
	cmd.args[3] = secondary_key ? 1 : 0;
	cmd.args[5] = endian_swap;
	cmd.opcode = BCM_AES_LOAD_KEY;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

/**
 * Load initialization vector
 *
 * @param       handle      Pointer to EHSM pointer
 * @param[in]   iv          Pointer to initialization vector
 * @param       endian_swap True for big endian
 *
 * @return  SEC_NO_ERROR, STATUS_NULL_POINTER, STATUS_DMA_BUFFER_UNALIGNED
 */
enum sec_return ehsm_aes_load_iv(struct ehsm_handle *handle,
				 const void *iv,
				 bool endian_swap)
{
	struct ehsm_command cmd;
	enum ehsm_status estat;

	ehsm_clear_command(&cmd);

	cmd.args[0] = ehsm_addr_low(iv);
	cmd.args[1] = ehsm_addr_hi(iv);
	cmd.args[3] = endian_swap;
	cmd.opcode = BCM_AES_LOAD_IV;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}

/**
 * Perform AES encryption/decryption
 *
 * @param       handle              Pointer to EHSM handle
 * @param[in]   src                 Pointer to source data, can be NULL
 * @param[out]  dest                Encrypted/decrypted data
 * @param       payload_len_byte    Number of bytes to encrypt/decrypt
 * @param       timeout             Number of rounds to poll DMA for completion,
 *                                  If 0, 10^^9
 * @param       is_new              Set true to begin a new encryption round,
 *                                  false to continue existing round.
 * @param       is_final            Set true if end of data, false if more data
 * @param	block_tag_gen	    Block tag generation.
 * @param[in]   src_list            List of source data, can be NULL of src set
 * @param[out]  dest_list           List of destination data, can be NULL if
 *                                  dest is set.
 *
 * @return      SEC_NO_ERROR, STATUS_NULL_POINTER,
 *              STATUS_DMA_DATA_BUFFER_UNALIGNED,
 *              STATUS_DMA_LINKED_LIST_UNALIGNED,
 *              STATUS_INVALID_REQUEST, STATUS_MSG_LENGTH_OVERFLOW
 *
 */
enum sec_return ehsm_aes_process(struct ehsm_handle *handle,
				 const void *src,
				 void *dest,
				 uint64_t payload_len_byte,
				 uint32_t timeout,
				 bool is_new,
				 bool is_final,
				 bool block_tag_gen __unused,
				 struct ehsm_dtd *src_list,
				 struct ehsm_dtd *dest_list)
{
	struct ehsm_command cmd;
	enum ehsm_status estat;

	ehsm_clear_command(&cmd);

	if (src) {
		cmd.args[0] = ehsm_addr_low(src);
		cmd.args[1] = ehsm_addr_hi(src);
	}
	if (dest) {
		cmd.args[2] = ehsm_addr_low(dest);
		cmd.args[3] = ehsm_addr_hi(dest);
	}
	cmd.args[4] = payload_len_byte & 0xffffffff;
	cmd.args[5] = payload_len_byte >> 32;
	cmd.args[6] = is_new ? 1 : 0;
	cmd.args[8] = timeout;
	cmd.args[10] = is_final ? 1 : 0;
	if (src_list) {
		cmd.args[12] = ehsm_addr_low(src_list);
		cmd.args[13] = ehsm_addr_hi(src_list);
	}
	if (dest_list) {
		cmd.args[14] = ehsm_addr_low(dest_list);
		cmd.args[15] = ehsm_addr_hi(dest_list);
	}
	cmd.opcode = BCM_AES_PROCESS;
	estat = ehsm_command(handle, &cmd);
	return (enum sec_return)estat;
}
