/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __IMX_DCP_H__
#define __IMX_DCP_H__

#include <compiler.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define DCP_SHA_BLOCK_SIZE    U(64)
#define DCP_AES128_BLOCK_SIZE U(16)
#define DCP_AES128_KEY_SIZE   DCP_AES128_BLOCK_SIZE
#define DCP_AES128_IV_SIZE    DCP_AES128_BLOCK_SIZE

enum dcp_key_mode {
	DCP_SRAM0 = 0,
	DCP_SRAM1,
	DCP_SRAM2,
	DCP_SRAM3,
	DCP_PAYLOAD,
	DCP_OTP,
};

enum dcp_aes_mode {
	DCP_ECB = 0,
	DCP_CBC,
};

enum dcp_aes_op {
	DCP_ENCRYPT = 0,
	DCP_DECRYPT,
};

enum dcp_hash_config {
	DCP_SHA1 = 0,
	DCP_SHA256,
};

enum dcp_channel {
	DCP_CHANN0 = 0,
	DCP_CHANN1,
	DCP_CHANN2,
	DCP_CHANN3,
	DCP_NB_CHANNELS,
};

/* DCP work packet descriptor is a hardware data structure */
struct dcp_descriptor {
	uint32_t next;
	uint32_t ctrl0;
	uint32_t ctrl1;
	/* Source buffer physical address */
	uint32_t src_buffer;
	/* Destination buffer physical address */
	uint32_t dest_buffer;
	uint32_t buff_size;
	/* Payload buffer physical address */
	uint32_t payload;
	uint32_t status;
};

struct dcp_align_buf {
	uint8_t *data;
	paddr_t paddr;
	size_t size;
};

struct dcp_data {
	struct dcp_descriptor desc;
	enum dcp_channel channel;
};

struct dcp_hash_data {
	struct dcp_data dcp_data;
	bool initialized;
	enum dcp_hash_config alg;
	struct dcp_align_buf ctx;
	size_t ctx_size;
};

struct dcp_hashalg {
	unsigned int type;
	unsigned int size;
};

struct dcp_cipher_data {
	struct dcp_data dcp_data;
	bool initialized;
	uint8_t iv[DCP_AES128_IV_SIZE];
	uint8_t key[DCP_AES128_KEY_SIZE];
	/* payload buffer holds the key and the iv */
	struct dcp_align_buf payload;
	size_t payload_size;
};

struct dcp_cipher_init {
	enum dcp_aes_op op;
	enum dcp_aes_mode mode;
	enum dcp_key_mode key_mode;
	uint8_t *key;
	uint8_t *iv;
};

/*
 * Perform AES-CMAC operation
 *
 * @init       Cipher operation context
 * @input      Input message
 * @input_size Input message size
 * @output     Output MAC
 */
TEE_Result dcp_cmac(struct dcp_cipher_init *init, uint8_t *input,
		    size_t input_size, uint8_t *output);

/*
 * Store key in the SRAM
 *
 * @key    Buffer containing the key to store (128 bit)
 * @index  Index of the key (0, 1, 2 or 3)
 */
TEE_Result dcp_store_key(uint32_t *key, unsigned int index);

/*
 * Initialize AES-128 operation
 *
 * @data   Cipher operation context
 * @init   Data for aesdata initialization
 */
TEE_Result dcp_cipher_do_init(struct dcp_cipher_data *data,
			      struct dcp_cipher_init *init);

/*
 * Update AES-128 operation
 *
 * @data  Cipher operation context
 * @src   Source data to encrypt/decrypt
 * @dst   [out] Destination buffer
 * @size  Size of source data in bytes, must be 16 bytes multiple
 */
TEE_Result dcp_cipher_do_update(struct dcp_cipher_data *data,
				const uint8_t *src, uint8_t *dst, size_t size);

/*
 * Finalize AES-128 operation
 *
 * @data Cipher operation context
 */
void dcp_cipher_do_final(struct dcp_cipher_data *data);

/*
 * Initialize hash operation
 *
 * @hashdata   Hash operation context
 */
TEE_Result dcp_sha_do_init(struct dcp_hash_data *hashdata);

/*
 * Update hash operation
 *
 * @hashdata   Hash operation context
 * @data       Buffer to hash
 * @len        Size of the input buffer in bytes
 */
TEE_Result dcp_sha_do_update(struct dcp_hash_data *hashdata,
			     const uint8_t *data, size_t len);

/*
 * Finalize the hash operation
 *
 * @hashdata      Hash operation context
 * @digest        [out] Result of the hash operation
 * @digest_size   Digest buffer size in bytes
 */
TEE_Result dcp_sha_do_final(struct dcp_hash_data *hashdata, uint8_t *digest,
			    size_t digest_size);

/*
 * Disable the use of the DCP unique key (0xFE in the DCP key-select field).
 */
void dcp_disable_unique_key(void);

/* Initialize DCP */
TEE_Result dcp_init(void);

#ifndef CFG_DT
static inline TEE_Result dcp_vbase(vaddr_t *base __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_DT */

#endif /* __IMX_DCP_H__ */
