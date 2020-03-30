// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <crypto/crypto_accel.h>
#include <crypto/ghash-ce-core.h>
#include <crypto/internal_aes-gcm.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <string.h>
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

void internal_aes_gcm_set_key(struct internal_aes_gcm_state *state,
			      const struct internal_aes_gcm_key *enc_key)
{
	uint64_t k[2];
	uint64_t a;
	uint64_t b;

	internal_aes_gcm_encrypt_block(enc_key, state->ctr, k);

	/* Store hash key in little endian and multiply by 'x' */
	b = get_be64(k);
	a = get_be64(k + 1);
	state->ghash_key.k[0] = (a << 1) | (b >> 63);
	state->ghash_key.k[1] = (b << 1) | (a >> 63);
	if (b >> 63)
		state->ghash_key.k[1] ^= 0xc200000000000000UL;
}

void internal_aes_gcm_ghash_update(struct internal_aes_gcm_state *state,
				   const void *head, const void *data,
				   size_t num_blocks)
{
	uint32_t vfp_state;
	uint64_t dg[2];

	get_be_block(dg, state->hash_state);

	vfp_state = thread_kernel_enable_vfp();

#ifdef CFG_HWSUPP_PMULT_64
	pmull_ghash_update_p64(num_blocks, dg, data, &state->ghash_key, head);
#else
	pmull_ghash_update_p8(num_blocks, dg, data, &state->ghash_key, head);
#endif
	thread_kernel_disable_vfp(vfp_state);

	put_be_block(state->hash_state, dg);
}

TEE_Result internal_aes_gcm_expand_enc_key(const void *key, size_t key_len,
					   struct internal_aes_gcm_key *enc_key)
{
	return crypto_accel_aes_expand_keys(key, key_len, enc_key->data, NULL,
					    sizeof(enc_key->data),
					    &enc_key->rounds);
}

void internal_aes_gcm_encrypt_block(const struct internal_aes_gcm_key *ek,
				    const void *src, void *dst)
{
	crypto_accel_aes_ecb_enc(dst, src, ek->data, ek->rounds, 1);
}

#ifdef ARM64
void internal_aes_gcm_update_payload_block_aligned(
				struct internal_aes_gcm_state *state,
				const struct internal_aes_gcm_key *ek,
				TEE_OperationMode mode, const void *src,
				size_t num_blocks, void *dst)
{
	uint32_t vfp_state;
	uint64_t dg[2];
	uint64_t ctr[2];

	get_be_block(dg, state->hash_state);
	get_be_block(ctr, state->ctr);

	vfp_state = thread_kernel_enable_vfp();

	pmull_gcm_load_round_keys(ek->data, ek->rounds);

	if (mode == TEE_MODE_ENCRYPT)
		pmull_gcm_encrypt(num_blocks, dg, dst, src, &state->ghash_key,
				  ctr, ek->rounds, state->buf_cryp);
	else
		pmull_gcm_decrypt(num_blocks, dg, dst, src, &state->ghash_key,
				  ctr, ek->rounds);

	thread_kernel_disable_vfp(vfp_state);

	put_be_block(state->ctr, ctr);
	put_be_block(state->hash_state, dg);
}
#endif /*ARM64*/
