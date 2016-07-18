/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * The license part of what was the "README" above:
 * License
 * -------
 *
 * This software may be distributed, used, and modified under the terms of
 * BSD license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name(s) of the above-listed copyright holder(s) nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <compiler.h>
#include "pager_private.h"
#include <tomcrypt.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

/*
 * Source copied from git://w1.fi/srv/git/hostap.git files
 * src/utils/common.h and src/crypto/aes-gcm.c
 *
 * The source has been modified for the pager use case.
 */

#define BLOCK_ALIGNMENT	sizeof(uint64_t)

static uint32_t get_be32(const void *a)
{
	return TEE_U32_FROM_BIG_ENDIAN(*(const uint32_t *)a);
}

static void put_be32(void *a, uint32_t val)
{
	*(uint32_t *)a = TEE_U32_TO_BIG_ENDIAN(val);
}

static void put_be64(void *a, uint64_t val)
{
	*(uint64_t *)a = TEE_U64_TO_BIG_ENDIAN(val);
}

static void aes_encrypt(symmetric_key *skey, const uint8_t *plain,
			uint8_t *crypt)
{
	aes_ecb_encrypt(plain, crypt, skey);
}

static void inc32(uint8_t *block)
{
	uint32_t val;

	val = get_be32(block + TEE_AES_BLOCK_SIZE - 4);
	val++;
	put_be32(block + TEE_AES_BLOCK_SIZE - 4, val);
}

static void xor_block(void *dst, const void *src)
{
	uint64_t *d = dst;
	const uint64_t *s = src;

	*d++ ^= *s++;
	*d++ ^= *s++;
}

static void shift_right_block(uint8_t *v)
{
	uint32_t next_val;
	uint32_t val;

	val = get_be32(v + 12);
	next_val = get_be32(v + 8);
	val >>= 1;
	val |= next_val << 31;
	put_be32(v + 12, val);

	val = next_val;
	next_val = get_be32(v + 4);
	val >>= 1;
	val |= next_val << 31;
	put_be32(v + 8, val);

	val = next_val;
	next_val = get_be32(v);
	val >>= 1;
	val |= next_val << 31;
	put_be32(v + 4, val);

	val = next_val;
	val >>= 1;
	put_be32(v, val);
}

/* Multiplication in GF(2^128) */
static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
	uint8_t v[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	unsigned i;
	unsigned j;

	memset(z, 0, TEE_AES_BLOCK_SIZE); /* Z_0 = 0^128 */
	memcpy(v, y, TEE_AES_BLOCK_SIZE); /* V_0 = Y */

	for (i = 0; i < TEE_AES_BLOCK_SIZE; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & BIT(7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}

static void ghash_start(uint8_t *y)
{
	/* Y_0 = 0^128 */
	memset(y, 0, TEE_AES_BLOCK_SIZE);
}


static void ghash(const uint8_t *h, const uint8_t *in, size_t len, uint8_t *out)
{
	size_t n;
	uint8_t tmp[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);

	/* We're only dealing with complete blocks */
	assert(!(len % TEE_AES_BLOCK_SIZE));

	for (n = 0; n < len; n += TEE_AES_BLOCK_SIZE) {
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(out, in + n);

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(out, h, tmp);
		memcpy(out, tmp, TEE_AES_BLOCK_SIZE);
	}
	/* Return Y_m */
}

static bool aes_gcm_init_hash_subkey(symmetric_key *skey, const uint8_t *key,
				     size_t key_len, uint8_t *H)
{
	if (aes_setup(key, key_len, 0, skey) != CRYPT_OK)
		return false;

	/* Generate hash subkey H = AES_K(0^128) */
	memset(H, 0, TEE_AES_BLOCK_SIZE);
	aes_encrypt(skey, H, H);
	return true;
}


static void aes_gcm_prepare_j0(const struct pager_aes_gcm_iv *iv, uint8_t *J0)
{
	/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
	memcpy(J0, iv, sizeof(*iv));
	memset(J0 + sizeof(*iv), 0, TEE_AES_BLOCK_SIZE - sizeof(*iv));
	J0[TEE_AES_BLOCK_SIZE - 1] = 0x01;
}

static void aes_gcm_core(symmetric_key *skey, bool enc, const uint8_t *J0,
			 const uint8_t *H, const uint8_t *in, size_t len,
			 uint8_t *out, uint8_t *tmp, uint8_t *S)
{
	uint8_t J0inc[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	size_t n;

	/* We're only dealing with complete blocks */
	assert(len && !(len % TEE_AES_BLOCK_SIZE));

	/*
	 * Below in the loop we're doing the encryption and hashing
	 * on each block interleaved since the encrypted data is stored
	 * in less secure memory.
	 */

	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	ghash_start(S);


	memcpy(J0inc, J0, TEE_AES_BLOCK_SIZE);
	inc32(J0inc);

	/* Full blocks */
	for (n = 0; n < len; n += TEE_AES_BLOCK_SIZE) {
		aes_encrypt(skey, J0inc, tmp);
		xor_block(tmp, in + n);
		memcpy(out + n, tmp, TEE_AES_BLOCK_SIZE);
		inc32(J0inc);

		/* Hash */
		if (enc)
			xor_block(S, tmp);
		else
			xor_block(S, in + n);
		gf_mult(S, H, tmp);
		memcpy(S, tmp, TEE_AES_BLOCK_SIZE);
	}

	put_be64(tmp, 0); /* no aad */
	put_be64(tmp + 8, len * 8);
	ghash(H, tmp, TEE_AES_BLOCK_SIZE, S);
}

/**
 * aes_gcm_ae - GCM-AE_K(IV, P, A)
 */
static bool aes_gcm_ae(const uint8_t *key, size_t key_len,
		       const struct pager_aes_gcm_iv *iv,
		       const uint8_t *plain, size_t plain_len,
		       uint8_t *crypt, uint8_t *tag)
{
	symmetric_key skey;
	uint8_t H[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	uint8_t J0[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	uint8_t S[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	uint8_t tmp[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);

	if (!aes_gcm_init_hash_subkey(&skey, key, key_len, H))
		return false;

	aes_gcm_prepare_j0(iv, J0);

	/* C = GCTR_K(inc_32(J_0), P) */
	aes_gcm_core(&skey, true, J0, H, plain, plain_len, crypt, tmp, S);

	/* T = MSB_t(GCTR_K(J_0, S)) */
	aes_encrypt(&skey, J0, tag);
	xor_block(tag, S);

	/* Return (C, T) */

	aes_done(&skey);

	return true;
}

/**
 * aes_gcm_ad - GCM-AD_K(IV, C, A, T)
 */
static bool aes_gcm_ad(const uint8_t *key, size_t key_len,
		       const struct pager_aes_gcm_iv *iv,
		       const uint8_t *crypt, size_t crypt_len,
		       const uint8_t *tag, uint8_t *plain)
{
	symmetric_key skey;
	uint8_t H[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	uint8_t J0[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	uint8_t S[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);
	uint8_t tmp[TEE_AES_BLOCK_SIZE] __aligned(BLOCK_ALIGNMENT);

	if (!aes_gcm_init_hash_subkey(&skey, key, key_len, H))
		return false;

	aes_gcm_prepare_j0(iv, J0);

	/* P = GCTR_K(inc_32(J_0), C) */
	aes_gcm_core(&skey, false, J0, H, crypt, crypt_len, plain, tmp, S);

	/* T' = MSB_t(GCTR_K(J_0, S)) */
	aes_encrypt(&skey, J0, tmp);
	xor_block(tmp, S);

	aes_done(&skey);

	return !buf_compare_ct(tag, tmp, TEE_AES_BLOCK_SIZE);
}

static bool check_block_alignment(const void *p)
{
	return !((vaddr_t)p % BLOCK_ALIGNMENT);
}

bool pager_aes_gcm_decrypt(const void *key, size_t keylen,
			   const struct pager_aes_gcm_iv *iv,
			   const uint8_t tag[PAGER_AES_GCM_TAG_LEN],
			   const void *src, void *dst, size_t datalen)
{
	if (!datalen || (datalen % TEE_AES_BLOCK_SIZE) ||
	    !check_block_alignment(src) || !check_block_alignment(dst))
		return false;
	return aes_gcm_ad(key, keylen, iv, src, datalen, tag, dst);
}

bool pager_aes_gcm_encrypt(const void *key, size_t keylen,
			   const struct pager_aes_gcm_iv *iv,
			   uint8_t tag[PAGER_AES_GCM_TAG_LEN],
			   const void *src, void *dst, size_t datalen)
{
	if (!datalen || (datalen % TEE_AES_BLOCK_SIZE) ||
	    !check_block_alignment(src) || !check_block_alignment(dst))
		return false;
	return aes_gcm_ae(key, keylen, iv, src, datalen, dst, tag);
}
