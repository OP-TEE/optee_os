// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto_accel.h>
#include <crypto/crypto.h>
#include <crypto/ghash-ce-core.h>
#include <crypto/internal_aes-gcm.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <string.h>
#include <types_ext.h>

#include "aes_armv8a_ce.h"

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

static void ghash_reflect(uint64_t h[2], const uint64_t k[2])
{
	uint64_t b = get_be64(k);
	uint64_t a = get_be64(k + 1);

	h[0] = (a << 1) | (b >> 63);
	h[1] = (b << 1) | (a >> 63);
	if (b >> 63)
		h[1] ^= 0xc200000000000000UL;
}

void internal_aes_gcm_set_key(struct internal_aes_gcm_state *state,
			      const struct internal_aes_gcm_key *enc_key)
{
	uint64_t k[2] = { 0 };
	uint64_t h[2] = { 0 };

	crypto_aes_enc_block(enc_key->data, sizeof(enc_key->data),
			     enc_key->rounds, state->ctr, k);

	ghash_reflect(state->ghash_key.h, k);

	internal_aes_gcm_gfmul(k, k, h);
	ghash_reflect(state->ghash_key.h2, h);

	internal_aes_gcm_gfmul(k, h, h);
	ghash_reflect(state->ghash_key.h3, h);

	internal_aes_gcm_gfmul(k, h, h);
	ghash_reflect(state->ghash_key.h4, h);
}

static void pmull_ghash_update(int num_blocks, uint64_t dg[2],
			       const uint8_t *src,
			       const struct internal_ghash_key *ghash_key,
			       const uint8_t *head)
{
#ifdef CFG_HWSUPP_PMULT_64
	pmull_ghash_update_p64(num_blocks, dg, src, ghash_key, head);
#else
	pmull_ghash_update_p8(num_blocks, dg, src, ghash_key, head);
#endif
}

void internal_aes_gcm_ghash_update(struct internal_aes_gcm_state *state,
				   const void *head, const void *data,
				   size_t num_blocks)
{
	uint32_t vfp_state;
	uint64_t dg[2];

	get_be_block(dg, state->hash_state);

	vfp_state = thread_kernel_enable_vfp();

	pmull_ghash_update(num_blocks, dg, data, &state->ghash_key, head);

	thread_kernel_disable_vfp(vfp_state);

	put_be_block(state->hash_state, dg);
}

static void encrypt_pl(struct internal_aes_gcm_state *state,
		       const struct internal_aes_gcm_key *ek, uint64_t dg[2],
		       const uint8_t *src, size_t num_blocks, uint8_t *dst)
{
	void *buf_cryp = state->buf_cryp;

	while (num_blocks) {
		ce_aes_xor_block(buf_cryp, buf_cryp, src);

		pmull_ghash_update(1, dg, buf_cryp, &state->ghash_key, NULL);
		memcpy(dst, buf_cryp, TEE_AES_BLOCK_SIZE);

		ce_aes_ecb_encrypt(buf_cryp, (const uint8_t *)state->ctr,
				   (const uint8_t *)ek->data, ek->rounds,
				   1, 1);
		internal_aes_gcm_inc_ctr(state);

		src += TEE_AES_BLOCK_SIZE;
		dst += TEE_AES_BLOCK_SIZE;
		num_blocks--;
	}
}

static void decrypt_pl(struct internal_aes_gcm_state *state,
		       const struct internal_aes_gcm_key *ek, uint64_t dg[2],
		       const uint8_t *src, size_t num_blocks, uint8_t *dst)
{
	while (num_blocks) {
		ce_aes_ctr_encrypt(dst, src, (const uint8_t *)ek->data,
				   ek->rounds, 1, (uint8_t *)state->ctr, 1);
		pmull_ghash_update(1, dg, src, &state->ghash_key, NULL);

		src += TEE_AES_BLOCK_SIZE;
		dst += TEE_AES_BLOCK_SIZE;
		num_blocks--;
	}
}

#ifdef ARM64
static void update_payload_2block(struct internal_aes_gcm_state *state,
				  const struct internal_aes_gcm_key *ek,
				  uint64_t dg[2], TEE_OperationMode mode,
				  const void *src, size_t num_blocks, void *dst)
{
	assert(num_blocks && !(num_blocks % 2));

	if (mode == TEE_MODE_ENCRYPT) {
		uint8_t ks[sizeof(state->buf_cryp) * 2] = { 0 };

		/*
		 * ks holds the encrypted counters of the next two blocks.
		 * pmull_gcm_encrypt() uses this to encrypt the first two
		 * blocks. When pmull_gcm_encrypt() returns is ks updated
		 * with the encrypted counters of the next two blocks. As
		 * we're only keeping one of these blocks we throw away
		 * block number two consequently decreases the counter by
		 * one.
		 */
		memcpy(ks, state->buf_cryp, sizeof(state->buf_cryp));

		pmull_gcm_load_round_keys(ek->data, ek->rounds);
		pmull_gcm_encrypt_block(ks + sizeof(state->buf_cryp),
					(uint8_t *)state->ctr, ek->rounds);
		internal_aes_gcm_inc_ctr(state);
		pmull_gcm_encrypt(num_blocks, dg, dst, src, &state->ghash_key,
				  state->ctr, NULL, ek->rounds, ks);
		memcpy(state->buf_cryp, ks, TEE_AES_BLOCK_SIZE);
		internal_aes_gcm_dec_ctr(state);
	} else {
		pmull_gcm_decrypt(num_blocks, dg, dst, src, &state->ghash_key,
				  state->ctr, ek->data, ek->rounds);
	}
}

/* Overriding the __weak function */
void
internal_aes_gcm_update_payload_blocks(struct internal_aes_gcm_state *state,
				       const struct internal_aes_gcm_key *ek,
				       TEE_OperationMode mode, const void *src,
				       size_t num_blocks, void *dst)
{
	size_t nb = ROUNDDOWN(num_blocks, 2);
	uint32_t vfp_state = 0;
	uint64_t dg[2] = { 0 };

	get_be_block(dg, state->hash_state);
	vfp_state = thread_kernel_enable_vfp();

	/*
	 * pmull_gcm_encrypt() and pmull_gcm_decrypt() can only handle
	 * blocks in multiples of two.
	 */
	if (nb)
		update_payload_2block(state, ek, dg, mode, src, nb, dst);

	if (nb != num_blocks) {
		/* There's a final block */
		const void *s = (const uint8_t *)src + nb * TEE_AES_BLOCK_SIZE;
		void *d = (uint8_t *)dst + nb * TEE_AES_BLOCK_SIZE;

		if (mode == TEE_MODE_ENCRYPT)
			encrypt_pl(state, ek, dg, s, 1, d);
		else
			decrypt_pl(state, ek, dg, s, 1, d);
	}

	thread_kernel_disable_vfp(vfp_state);
	put_be_block(state->hash_state, dg);
}
#endif /*ARM64*/

#ifdef ARM32
/* Overriding the __weak function */
void
internal_aes_gcm_update_payload_blocks(struct internal_aes_gcm_state *state,
				       const struct internal_aes_gcm_key *ek,
				       TEE_OperationMode mode, const void *src,
				       size_t num_blocks, void *dst)
{
	uint64_t dg[2] = { 0 };
	uint32_t vfp_state = 0;

	assert(!state->buf_pos && num_blocks);
	get_be_block(dg, state->hash_state);
	vfp_state = thread_kernel_enable_vfp();

	if (mode == TEE_MODE_ENCRYPT)
		encrypt_pl(state, ek, dg, src, num_blocks, dst);
	else
		decrypt_pl(state, ek, dg, src, num_blocks, dst);

	thread_kernel_disable_vfp(vfp_state);
	put_be_block(state->hash_state, dg);
}
#endif
