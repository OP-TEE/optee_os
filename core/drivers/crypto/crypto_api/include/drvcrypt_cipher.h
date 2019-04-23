/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 DRV
 *
 * @file    drvcrypt_cipher.h
 *
 * @brief   Cipher interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_CIPHER_H__
#define __DRVCRYPT_CIPHER_H__

#include <crypto/crypto_impl.h>
#include <tee_api_types.h>
#include <util.h>

/** @brief  AES Algorithm type id */
#define DRV_AES_ID		BIT32(5)
/** @brief  DES Algorithm type id */
#define DRV_DES_ID		BIT32(6)
/** @brief  Triple-DES Algorithm type id */
#define DRV_DES3_ID		BIT32(7)

/** @brief  Cipher ID mask */
#define DRV_CIPHER_ID_MASK	(DRV_DES3_ID | DRV_DES_ID | DRV_AES_ID)
/** @brief  Return the Cipher algo id */
#define DRV_CIPHER_ID(algo)	(algo & DRV_CIPHER_ID_MASK)

/**
 * @brief   Cipher Algorithm enumerate
 */
enum drvcrypt_cipher_id {
	AES_ECB_NOPAD = DRV_AES_ID,   ///< AES Algo mode ECB NO PAD
	AES_CBC_NOPAD,                ///< AES Algo mode CBC NO PAD
	AES_CTR,                      ///< AES Algo mode CTR
	AES_CTS,                      ///< AES Algo mode CTS
	AES_XTS,                      ///< AES Algo mode XTS
	AES_CBC_MAC,                  ///< AES Algo mode CBC MAC
	MAX_AES_ID,                   ///< Maximum AES ID
	DES_ECB_NOPAD = DRV_DES_ID,   ///< DES Algo mode ECB NO PAD
	DES_CBC_NOPAD,                ///< DES Algo mode CBC NO PAD
	DES_CBC_MAC,                  ///< DES Algo mode CBC MAC
	MAX_DES_ID,                   ///< Maximum DES ID
	DES3_ECB_NOPAD = DRV_DES3_ID, ///< Triple-DES Algo mode ECB NO PAD
	DES3_CBC_NOPAD,               ///< Triple-DES Algo mode CBC NO PAD
	DES3_CBC_MAC,                 ///< Triple-DES Algo mode CBC MAC
	MAX_DES3_ID,                  ///< Maximum Triple-DES ID
};

/** @brief  Maximum AES supported */
#define MAX_AES_SUPPORTED	(MAX_AES_ID - DRV_AES_ID)
/** @brief  Maximum DES supported */
#define MAX_DES_SUPPORTED	(MAX_DES_ID - DRV_DES_ID)
/** @brief  Maximum Triple-DES supported */
#define MAX_DES3_SUPPORTED	(MAX_DES3_ID - DRV_DES3_ID)

/**
 * @brief  Format the CIPHER context to keep the reference to the
 *         operation driver
 */
struct crypto_cipher {
	struct crypto_cipher_ctx cipher_ctx; ///< Crypto Cipher API context

	void                   *ctx; ///< Cipher Context
	struct drvcrypt_cipher *op;  ///< Reference to the operation
};

/**
 * @brief   Cipher Algorithm initialization data
 */
struct drvcrypt_cipher_init {
	void                *ctx;     ///< Software Context
	bool                encrypt;  ///< Encrypt or decrypt direction
	struct drvcrypt_buf key1;     ///< First Key
	struct drvcrypt_buf key2;     ///< Second Key
	struct drvcrypt_buf iv;       ///< Initial Vector
};

/**
 * @brief   Cipher Algorithm update data
 */
struct drvcrypt_cipher_update {
	void                *ctx;     ///< Software Context
	bool                encrypt;  ///< Encrypt or decrypt direction
	bool                last;     ///< Last block to handle
	struct drvcrypt_buf src;      ///< Buffer source (Message or Cipher)
	struct drvcrypt_buf dst;      ///< Buffer dest (Message or Cipher)
};

/**
 * @brief   DRV Crypto Library Cipher driver operations
 *
 */
struct drvcrypt_cipher {
	///< Allocates of the Software context
	TEE_Result (*alloc_ctx)(void **ctx, enum drvcrypt_cipher_id algo);
	///< Free of the Software context
	void (*free_ctx)(void *ctx);
	///< Initialize the cipher operation
	TEE_Result (*init)(struct drvcrypt_cipher_init *dinit);
	///< Update the cipher operation
	TEE_Result (*update)(struct drvcrypt_cipher_update *dupdate);
	///< Finalize the cipher operation
	void (*final)(void *ctx);
	///< Get Cipher block size
	TEE_Result (*block_size)(enum drvcrypt_cipher_id algo, size_t *size);

	///< Copy Cipher context
	void (*cpy_state)(void *dst_ctx, void *src_ctx);
};

#endif /* __DRVCRYPT_CIPHER_H__ */
