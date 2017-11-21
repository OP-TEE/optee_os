/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <crypto/internal_aes-gcm.h>
#include <crypto/ghash-ce-core.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <tomcrypt.h>
#include <types_ext.h>

static void get_be_block(void *dst, const void *src)
{
	uint64_t *d = dst;

	d[1] = get_be64(src);
	d[0] = get_be64((const uint8_t *)src + 8);
}

static void put_be_block(void *dst, const void *src)
{
	const uint64_t *s = src;

	put_be64(dst, s[1]);
	put_be64((uint8_t *)dst + 8, s[0]);
}

TEE_Result internal_aes_gcm_set_key(struct internal_aes_gcm_ctx *ctx,
				    const void *key, size_t key_len)
{
	TEE_Result res;
	uint64_t k[2];
	uint64_t a;
	uint64_t b;

	res = internal_aes_gcm_expand_enc_key(key, key_len, ctx->enc_key,
					      &ctx->rounds);
	if (res)
		return res;

	internal_aes_gcm_encrypt_block(ctx, ctx->ctr, ctx->hash_subkey);

	/* Store hash key in little endian and multiply by 'x' */
	b = get_be64(ctx->hash_subkey);
	a = get_be64(ctx->hash_subkey + 8);
	k[0] = (a << 1) | (b >> 63);
	k[1] = (b << 1) | (a >> 63);
	if (b >> 63)
		k[1] ^= 0xc200000000000000UL;

	memcpy(ctx->hash_subkey, k, TEE_AES_BLOCK_SIZE);
	return TEE_SUCCESS;
}

void internal_aes_gcm_ghash_update(struct internal_aes_gcm_ctx *ctx,
				   const void *head, const void *data,
				 size_t num_blocks)
{
	uint32_t vfp_state;
	uint64_t dg[2];
	uint64_t *k;

	get_be_block(dg, ctx->hash_state);

	k = (void *)ctx->hash_subkey;

	vfp_state = thread_kernel_enable_vfp();

#ifdef CFG_HWSUPP_PMULL
	pmull_ghash_update_p64(num_blocks, dg, data, k, head);
#else
	pmull_ghash_update_p8(num_blocks, dg, data, k, head);
#endif
	thread_kernel_disable_vfp(vfp_state);

	put_be_block(ctx->hash_state, dg);
}

#ifdef ARM64
static uint32_t ror32(uint32_t word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

TEE_Result internal_aes_gcm_expand_enc_key(const void *key, size_t key_len,
					   uint64_t *enc_key,
					   unsigned int *rounds)
{
	/* The AES key schedule round constants */
	static uint8_t const rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
	};
	uint32_t vfp_state;
	uint32_t kwords = key_len / sizeof(uint32_t);
	uint32_t *ek = (uint32_t *)enc_key;
	unsigned int i;

	if (key_len != 16 && keylen != 24 && keylen != 32)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(enc_key, key, key_len);
	/*
	 * # of rounds specified by AES:
	 * 128 bit key          10 rounds
	 * 192 bit key          12 rounds
	 * 256 bit key          14 rounds
	 * => n byte key        => 6 + (n/4) rounds
	 */
	*rounds = 6 + key_len / 4;

	vfp_state = thread_kernel_enable_vfp();
	for (i = 0; i < sizeof(rcon); i++) {
		uint32_t *rki = ek + (i * kwords);
		uint32_t *rko = rki + kwords;

		rko[0] = ror32(pmull_gcm_aes_sub(rki[kwords - 1]), 8) ^
			 rcon[i] ^ rki[0];
		rko[1] = rko[0] ^ rki[1];
		rko[2] = rko[1] ^ rki[2];
		rko[3] = rko[2] ^ rki[3];

		if (key_len == 24) {
			if (i >= 7)
				break;
			rko[4] = rko[3] ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
		} else if (key_len == 32) {
			if (i >= 6)
				break;
			rko[4] = pmull_gcm_aes_sub(rko[3]) ^ rki[4];
			rko[5] = rko[4] ^ rki[5];
			rko[6] = rko[5] ^ rki[6];
			rko[7] = rko[6] ^ rki[7];
		}
	}

	thread_kernel_disable_vfp(vfp_state);
	return TEE_SUCCESS;
}

void internal_aes_gcm_encrypt_block(struct internal_aes_gcm_ctx *ctx,
				    const void *src, void *dst)
{
	uint32_t vfp_state;

	vfp_state = thread_kernel_enable_vfp();

	pmull_gcm_load_round_keys(ctx->enc_key, ctx->rounds);
	pmull_gcm_encrypt_block(dst, src, ctx->rounds);

	thread_kernel_disable_vfp(vfp_state);
}

void
internal_aes_gcm_update_payload_block_aligned(struct internal_aes_gcm_ctx *ctx,
					      TEE_OperationMode m,
					      const void *src,
					      size_t num_blocks, void *dst)
{
	uint32_t vfp_state;
	uint64_t dg[2];
	uint64_t ctr[2];
	uint64_t *k;

	get_be_block(dg, ctx->hash_state);
	get_be_block(ctr, ctx->ctr);

	k = (void *)ctx->hash_subkey;

	vfp_state = thread_kernel_enable_vfp();

	pmull_gcm_load_round_keys(ctx->enc_key, ctx->rounds);

	if (m == TEE_MODE_ENCRYPT)
		pmull_gcm_encrypt(num_blocks, dg, dst, src, k, ctr, ctx->rounds,
				  ctx->buf_cryp);
	else
		pmull_gcm_decrypt(num_blocks, dg, dst, src, k, ctr,
				  ctx->rounds);

	thread_kernel_disable_vfp(vfp_state);

	put_be_block(ctx->ctr, ctr);
	put_be_block(ctx->hash_state, dg);
}
#endif /*ARM64*/
