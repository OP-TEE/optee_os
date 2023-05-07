/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020-2023, Linaro Limited
 */

#ifndef __CRYPTO_CRYPTO_ACCEL_H
#define __CRYPTO_CRYPTO_ACCEL_H

#include <tee_api_types.h>

TEE_Result crypto_accel_aes_expand_keys(const void *key, size_t key_len,
					void *enc_key, void *dec_key,
					size_t expanded_key_len,
					unsigned int *round_count);

void crypto_accel_aes_ecb_enc(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count);
void crypto_accel_aes_ecb_dec(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count);

void crypto_accel_aes_cbc_enc(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count, void *iv);
void crypto_accel_aes_cbc_dec(void *out, const void *in, const void *key,
			      unsigned int round_count,
			      unsigned int block_count, void *iv);

void crypto_accel_aes_ctr_be_enc(void *out, const void *in, const void *key,
				 unsigned int round_count,
				 unsigned int block_count, void *iv);

void crypto_accel_aes_xts_enc(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count, const void *key2,
			      void *tweak);
void crypto_accel_aes_xts_dec(void *out, const void *in, const void *key1,
			      unsigned int round_count,
			      unsigned int block_count, const void *key2,
			      void *tweak);

void crypto_accel_sha1_compress(uint32_t state[5], const void *src,
				unsigned int block_count);
void crypto_accel_sha256_compress(uint32_t state[8], const void *src,
				  unsigned int block_count);
void crypto_accel_sha512_compress(uint64_t state[8], const void *src,
				  unsigned int block_count);
void crypto_accel_sha3_compress(uint64_t state[25], const void *src,
				unsigned int block_count,
				unsigned int digest_size);
void crypto_accel_sm3_compress(uint32_t state[8], const void *src,
			       unsigned int block_count);

void crypto_accel_sm4_setkey_enc(uint32_t sk[32], const uint8_t key[16]);
void crypto_accel_sm4_setkey_dec(uint32_t sk[32], const uint8_t key[16]);
void crypto_accel_sm4_ecb_enc(void *out, const void *in, const void *key,
			      unsigned int len);
void crypto_accel_sm4_cbc_enc(void *out, const void *in, const void *key,
			      unsigned int len, void *iv);
void crypto_accel_sm4_cbc_dec(void *out, const void *in, const void *key,
			      unsigned int len, void *iv);
void crypto_accel_sm4_ctr_enc(void *out, const void *in, const void *key,
			      unsigned int len, void *iv);
void crypto_accel_sm4_xts_enc(void *out, const void *in, const void *key1,
			      const void *key2, unsigned int len, void *iv);
void crypto_accel_sm4_xts_dec(void *out, const void *in, const void *key1,
			      const void *key2, unsigned int len, void *iv);

#endif /*__CRYPTO_CRYPTO_ACCEL_H*/
