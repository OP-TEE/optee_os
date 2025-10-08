/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Marvell.
 */

#ifndef __EHSM_AES_H__
#define __EHSM_AES_H__
#include <stdint.h>
#include <stdbool.h>

#include "ehsm.h"
#include "ehsm-security.h"

enum ehsm_aes_mode {
	EHSM_AES_MODE_ECB       = 0,
	EHSM_AES_MODE_CBC       = 1,
	EHSM_AES_MODE_CTR       = 2,
	EHSM_AES_MODE_XTS       = 3,
	EHSM_AES_MODE_KEY_WRAP  = 4,
	EHSM_AES_MODE_CFB       = 5,
	EHSM_AES_MODE_OFB       = 6,
	EHSM_AES_MODE_GCM       = 7,
};

enum ehsm_aes_key_size {
	EHSM_AES_KEY_128        = 128,
	EHSM_AES_KEY_192        = 192,
	EHSM_AES_KEY_256        = 256,
};

/*
 * Reset AES engine and zeroize key registers
 *
 * @param       handle      Pointer to EHSM handle
 *
 * @return      SEC_NO_ERROR
 */
enum sec_return ehsm_aes_zeroize(struct ehsm_handle *handle);

/*
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
			      bool endian_swap);

/*
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
				  bool endian_swap);

/*
 * Load a plaintext key into the EHSM register bank
 *
 * @param       handle          EHSM handle pointer
 * @param       key_size	128, 192, or 256
 * @param[in]   key             Key pointer
 * @param       secondary_key   Load key into secondary registers
 * @param       endian_swap     Set true for big endian
 *
 * @return  SEC_NO_ERROR, STATUS_DISABLED_IN_FIPS_MODE,
 *          STATUS_UNSUPPORTED_PARAMETER, STATUS_NULL_POINTER,
 *          STATUS_DMA_BUFFER_UNALIGNED, STATUS_DATA_BUFFER_UNALIGNED
 */
enum sec_return ehsm_aes_load_key(struct ehsm_handle *handle,
				  enum ehsm_aes_key_size key_size,
				  const void *key,
				  bool secondary_key,
				  bool endian_swap);

/*
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
				 bool endian_swap);

/*
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
				 struct ehsm_dtd *dest_list);
#endif /* __EHSM_AES_H__ */
