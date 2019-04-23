/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    local.h
 *
 * @brief   CAAM Cipher Local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_cipher.h>

/**
 * @brief    Maximum number of entry in the descriptor
 */
#define MAX_DESC_ENTRIES	14

/**
 * @brief   Definition of flags tagging which key(s) is required
 */
#define NEED_KEY1	BIT(0)
#define NEED_KEY2	BIT(1)
#define NEED_IV		BIT(2)
#define NEED_TWEAK	BIT(3)

/**
 * @brief   Cipher Algorithm definition
 */
struct cipheralg {
	uint32_t type;         ///< Algo type for operation
	uint8_t  size_block;   ///< Computing block size
	uint8_t  size_ctx;     ///< CAAM Context Register size
	uint8_t  ctx_offset;   ///< CAAM Context Register offset
	uint8_t  require_key;  ///< Tag defining key(s) required

	struct defkey def_key; ///< Key size accepted

	TEE_Result (*update)(struct drvcrypt_cipher_update *dupdate);
};

/**
 * @brief   Full Cipher data SW context
 */
struct cipherdata {
	descPointer_t descriptor;         ///< Job descriptor

	bool encrypt;                     ///< Encrypt direction

	struct caambuf key1;              ///< First Key
	struct caambuf key2;              ///< Second Key

	struct caambuf tweak;             ///< XTS Tweak

	struct caambuf ctx;               ///< CAAM Context Register

	struct caamblock blockbuf;        ///< Temporary Block buffer

	enum drvcrypt_cipher_id algo_id;  ///< Cipher Algorithm Id
	const struct cipheralg  *alg;     ///< Reference to the algo constants
};

/**
 * @brief   Update of the cipher operation of complete block except
 *          if last block. Last block can be partial block.
 *
 * @param[in]  ctx      Cipher context
 * @param[in]  savectx  Save or not the context
 * @param[in]  keyid    Id of the key to be used during operation
 * @param[in]  encrypt  Encrypt or decrypt direction
 * @param[in]  src      Source data to encrypt/decrypt
 * @param[out] dst      Destination data encrypted/decrypted
 *
 * @retval CAAM_NO_ERROR  Success
 * @retval CAAM_FAILURE   Other Error
 */
enum CAAM_Status do_block(struct cipherdata *ctx,
				bool savectx, uint8_t keyid, bool encrypt,
				struct sgtbuf *src,
				struct sgtbuf *dst);

/**
 * @brief   Update of the cipher CMAC operation of complete block except
 *          if last block. Last block can be partial block.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 * @retval TEE_ERROR_SHORT_BUFFER    Output buffer too short
 */
TEE_Result do_update_cmac(struct drvcrypt_cipher_update *dupdate);

/**
 * @brief   Update of the cipher operation in xts mode.
 *
 * @param[in] dupdate  Data update object
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_GENERIC         Other Error
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS  Bad Parameters
 */
TEE_Result do_update_xts(struct drvcrypt_cipher_update *dupdate);

#endif /* __LOCAL_H__ */

