// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_lite.h>
#include <kernel/panic.h>
#include <mpalib.h>
#include <stdlib.h>
#include <string_ext.h>
#include <string.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_utl.h>
#include <tomcrypt.h>
#include "tomcrypt_mpa.h"
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#if defined(CFG_WITH_VFP)
#include <tomcrypt_arm_neon.h>
#include <kernel/thread.h>
#endif

/* Random generator */
static int prng_mpa_start(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_add_entropy(const unsigned char *in __unused,
				unsigned long inlen __unused,
				union Prng_state *prng __unused)
{
	/* No entropy is required */
	return CRYPT_OK;
}

static int prng_mpa_ready(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static unsigned long prng_mpa_read(unsigned char *out, unsigned long outlen,
				   union Prng_state *prng __unused)
{
	if (crypto_rng_read(out, outlen))
		return 0;

	return outlen;
}

static int prng_mpa_done(union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_export(unsigned char *out __unused,
			   unsigned long *outlen __unused,
			   union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_import(const unsigned char *in  __unused,
			   unsigned long inlen __unused,
			   union Prng_state *prng __unused)
{
	return CRYPT_OK;
}

static int prng_mpa_test(void)
{
	return CRYPT_OK;
}

static const struct ltc_prng_descriptor prng_mpa_desc = {
	.name = "prng_mpa",
	.export_size = 64,
	.start = &prng_mpa_start,
	.add_entropy = &prng_mpa_add_entropy,
	.ready = &prng_mpa_ready,
	.read = &prng_mpa_read,
	.done = &prng_mpa_done,
	.pexport = &prng_mpa_export,
	.pimport = &prng_mpa_import,
	.test = &prng_mpa_test,
};

/*
 * tee_ltc_reg_algs(): Registers
 *	- algorithms
 *	- prng (pseudo random generator)
 */

static void tee_ltc_reg_algs(void)
{
#if defined(CFG_CRYPTO_AES)
	register_cipher(&aes_desc);
#endif
#if defined(CFG_CRYPTO_DES)
	register_cipher(&des_desc);
	register_cipher(&des3_desc);
#endif
	register_prng(&prng_mpa_desc);
}

#if defined(_CFG_CRYPTO_WITH_CIPHER) || defined(_CFG_CRYPTO_WITH_MAC) || \
	defined(_CFG_CRYPTO_WITH_AUTHENC)
/*
 * Compute the LibTomCrypt "cipherindex" given a TEE Algorithm "algo"
 * Return
 * - TEE_SUCCESS in case of success,
 * - TEE_ERROR_BAD_PARAMETERS in case algo is not a valid algo
 * - TEE_ERROR_NOT_SUPPORTED in case algo is not supported by LTC
 * Return -1 in case of error
 */
static TEE_Result tee_algo_to_ltc_cipherindex(uint32_t algo,
					      int *ltc_cipherindex)
{
	switch (algo) {
#if defined(CFG_CRYPTO_AES)
	case TEE_ALG_AES_ECB_NOPAD:
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CTS:
	case TEE_ALG_AES_XTS:
		*ltc_cipherindex = find_cipher("aes");
		break;
#endif
#if defined(CFG_CRYPTO_DES)
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
		*ltc_cipherindex = find_cipher("des");
		break;
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		*ltc_cipherindex = find_cipher("3des");
		break;
#endif
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (*ltc_cipherindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;
	else
		return TEE_SUCCESS;
}
#endif /* defined(_CFG_CRYPTO_WITH_CIPHER) ||
	* defined(_CFG_CRYPTO_WITH_MAC) || defined(_CFG_CRYPTO_WITH_AUTHC)
	*/

/******************************************************************************
 * Asymmetric algorithms
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_ACIPHER)

#if defined(CFG_WITH_PAGER)
#include <mm/tee_pager.h>
#include <util.h>
#include <mm/core_mmu.h>

/* allocate pageable_zi vmem for mpa scratch memory pool */
static struct mempool *get_mpa_scratch_memory_pool(void)
{
	size_t size;
	void *data;

	size = ROUNDUP((LTC_MEMPOOL_U32_SIZE * sizeof(uint32_t)),
			SMALL_PAGE_SIZE);
	data = tee_pager_alloc(size, 0);
	if (!data)
		panic();

	return mempool_alloc_pool(data, size, tee_pager_release_phys);
}
#else /* CFG_WITH_PAGER */
static struct mempool *get_mpa_scratch_memory_pool(void)
{
	static uint32_t data[LTC_MEMPOOL_U32_SIZE] __aligned(__alignof__(long));

	return mempool_alloc_pool(data, sizeof(data), NULL);
}
#endif

static void tee_ltc_alloc_mpa(void)
{
	static mpa_scratch_mem_base mem;

	/*
	 * The default size (bits) of a big number that will be required it
	 * equals the max size of the computation (for example 4096 bits),
	 * multiplied by 2 to allow overflow in computation
	 */
	mem.bn_bits = CFG_CORE_BIGNUM_MAX_BITS * 2;
	mem.pool = get_mpa_scratch_memory_pool();
	if (!mem.pool)
		panic();
	init_mpa_tomcrypt(&mem);
}

#if defined(CFG_CRYPTO_MBEDTLS)

static TEE_Result copy_bignum_mpa_to_mpi(const struct bignum *from,
				struct bignum *to)
{
	size_t len;
	void *buf = NULL;
	int ret;

	len = mp_unsigned_bin_size((struct bignum *)from);
	buf = calloc(1, len);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	mp_to_unsigned_bin((struct bignum *)from, buf);
	ret = crypto_bignum_bin2bn(buf, len, to);
	free(buf);
	return ret;
}

static TEE_Result copy_bignum_mpi_to_mpa(const struct bignum *from,
				struct bignum *to)
{
	size_t len;
	void *buf = NULL;
	int ret;

	len = crypto_bignum_num_bytes((struct bignum *)from);
	buf = calloc(1, len);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	crypto_bignum_bn2bin(from, buf);
	ret = mp_read_unsigned_bin(to, buf, len);
	free(buf);
	if (ret != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

#endif

static TEE_Result __maybe_unused convert_ltc_verify_status(int ltc_res,
							   int ltc_stat)
{
	switch (ltc_res) {
	case CRYPT_OK:
		if (ltc_stat == 1)
			return TEE_SUCCESS;
		else
			return TEE_ERROR_SIGNATURE_INVALID;
	case CRYPT_INVALID_PACKET:
		return TEE_ERROR_SIGNATURE_INVALID;
	default:
		return TEE_ERROR_GENERIC;
	}
}

#if defined(CFG_CRYPTO_DSA)

TEE_Result crypto_acipher_alloc_dsa_keypair(struct dsa_keypair *s,
					    size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->g = crypto_bignum_allocate(key_size_bits);
	if (!s->g)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->p = crypto_bignum_allocate(key_size_bits);
	if (!s->p)
		goto err;
	s->q = crypto_bignum_allocate(key_size_bits);
	if (!s->q)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
		goto err;
	s->x = crypto_bignum_allocate(key_size_bits);
	if (!s->x)
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	crypto_bignum_free(s->y);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_alloc_dsa_public_key(struct dsa_public_key *s,
					       size_t key_size_bits)
{
	memset(s, 0, sizeof(*s));
	s->g = crypto_bignum_allocate(key_size_bits);
	if (!s->g)
		return TEE_ERROR_OUT_OF_MEMORY;
	s->p = crypto_bignum_allocate(key_size_bits);
	if (!s->p)
		goto err;
	s->q = crypto_bignum_allocate(key_size_bits);
	if (!s->q)
		goto err;
	s->y = crypto_bignum_allocate(key_size_bits);
	if (!s->y)
		goto err;
	return TEE_SUCCESS;
err:
	crypto_bignum_free(s->g);
	crypto_bignum_free(s->p);
	crypto_bignum_free(s->q);
	return TEE_ERROR_OUT_OF_MEMORY;
}

TEE_Result crypto_acipher_gen_dsa_key(struct dsa_keypair *key, size_t key_size)
{
	TEE_Result res;
	dsa_key ltc_tmp_key;
	size_t group_size, modulus_size = key_size / 8;
	int ltc_res;

	if (modulus_size <= 128)
		group_size = 20;
	else if (modulus_size <= 256)
		group_size = 30;
	else if (modulus_size <= 384)
		group_size = 35;
	else
		group_size = 40;

	/* Generate the DSA key */
	ltc_res = dsa_make_key(NULL, find_prng("prng_mpa"), group_size,
			       modulus_size, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.p) != key_size) {
		dsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* Copy the key */
#if defined(CFG_CRYPTO_MBEDTLS)
		res = copy_bignum_mpa_to_mpi(ltc_tmp_key.g, key->g);
		if (res != TEE_SUCCESS) {
			dsa_free(&ltc_tmp_key);
			return res;
		}
		res = copy_bignum_mpa_to_mpi(ltc_tmp_key.p, key->p);
		if (res != TEE_SUCCESS) {
			dsa_free(&ltc_tmp_key);
			return res;
		}
		res = copy_bignum_mpa_to_mpi(ltc_tmp_key.q, key->q);
		if (res != TEE_SUCCESS) {
			dsa_free(&ltc_tmp_key);
			return res;
		}
		res = copy_bignum_mpa_to_mpi(ltc_tmp_key.y, key->y);
		if (res != TEE_SUCCESS) {
			dsa_free(&ltc_tmp_key);
			return res;
		}
		res = copy_bignum_mpa_to_mpi(ltc_tmp_key.x, key->x);
		if (res != TEE_SUCCESS) {
			dsa_free(&ltc_tmp_key);
			return res;
		}
#else
		ltc_mp.copy(ltc_tmp_key.g, key->g);
		ltc_mp.copy(ltc_tmp_key.p, key->p);
		ltc_mp.copy(ltc_tmp_key.q, key->q);
		ltc_mp.copy(ltc_tmp_key.y, key->y);
		ltc_mp.copy(ltc_tmp_key.x, key->x);
		res = TEE_SUCCESS;
#endif
		/* Free the tempory key */
		dsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result crypto_acipher_dsa_sign(uint32_t algo, struct dsa_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size;
	int ltc_res;
	void *r, *s;
	dsa_key ltc_key = {
		.type = PK_PRIVATE,
		.qord = mp_unsigned_bin_size(key->g),
#if !defined(CFG_CRYPTO_MBEDTLS)
		.g = key->g,
		.p = key->p,
		.q = key->q,
		.y = key->y,
		.x = key->x,
#endif
	};

	if (algo != TEE_ALG_DSA_SHA1 &&
	    algo != TEE_ALG_DSA_SHA224 &&
	    algo != TEE_ALG_DSA_SHA256) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto err;
	}

#if defined(CFG_CRYPTO_MBEDTLS)
	ltc_mp.init_size(crypto_bignum_num_bits(key->g), &ltc_key.g);
	ltc_mp.init_size(crypto_bignum_num_bits(key->p), &ltc_key.p);
	ltc_mp.init_size(crypto_bignum_num_bits(key->q), &ltc_key.q);
	ltc_mp.init_size(crypto_bignum_num_bits(key->y), &ltc_key.y);
	ltc_mp.init_size(crypto_bignum_num_bits(key->x), &ltc_key.x);

	res = copy_bignum_mpi_to_mpa(key->g, ltc_key.g);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_bignum_mpi_to_mpa(key->p, ltc_key.p);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_bignum_mpi_to_mpa(key->q, ltc_key.q);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_bignum_mpi_to_mpa(key->y, ltc_key.y);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_bignum_mpi_to_mpa(key->x, ltc_key.x);
	if (res != TEE_SUCCESS)
		goto err;
#endif

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo),
				       &hash_size);
	if (res != TEE_SUCCESS)
		goto err;
	if (mp_unsigned_bin_size(ltc_key.q) < hash_size)
		hash_size = mp_unsigned_bin_size(ltc_key.q);
	if (msg_len != hash_size) {
		res = TEE_ERROR_SECURITY;
		goto err;
	}

	if (*sig_len < 2 * mp_unsigned_bin_size(ltc_key.q)) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key.q);
		res = TEE_ERROR_SHORT_BUFFER;
		goto err;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	ltc_res = dsa_sign_hash_raw(msg, msg_len, r, s, NULL,
				    find_prng("prng_mpa"), &ltc_key);

	if (ltc_res == CRYPT_OK) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key.q);
		memset(sig, 0, *sig_len);
		mp_to_unsigned_bin(r, (uint8_t *)sig + *sig_len/2 -
				   mp_unsigned_bin_size(r));
		mp_to_unsigned_bin(s, (uint8_t *)sig + *sig_len -
				   mp_unsigned_bin_size(s));
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_GENERIC;
	}

	mp_clear_multi(r, s, NULL);

err:
#if defined(CFG_CRYPTO_MBEDTLS)
	dsa_free(&ltc_key);
#endif
	return res;
}

TEE_Result crypto_acipher_dsa_verify(uint32_t algo, struct dsa_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	int ltc_stat, ltc_res;
	void *r, *s;
	dsa_key ltc_key = {
		.type = PK_PUBLIC,
		.qord = mp_unsigned_bin_size(key->g),
#if !defined(CFG_CRYPTO_MBEDTLS)
		.g = key->g,
		.p = key->p,
		.q = key->q,
		.y = key->y
#endif
	};

	if (algo != TEE_ALG_DSA_SHA1 &&
	    algo != TEE_ALG_DSA_SHA224 &&
	    algo != TEE_ALG_DSA_SHA256) {
		res = TEE_ERROR_NOT_IMPLEMENTED;
		goto err;
	}

#if defined(CFG_CRYPTO_MBEDTLS)
	ltc_mp.init_size(crypto_bignum_num_bits(key->g), &ltc_key.g);
	ltc_mp.init_size(crypto_bignum_num_bits(key->p), &ltc_key.p);
	ltc_mp.init_size(crypto_bignum_num_bits(key->q), &ltc_key.q);
	ltc_mp.init_size(crypto_bignum_num_bits(key->y), &ltc_key.y);

	res = copy_bignum_mpi_to_mpa(key->g, ltc_key.g);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_bignum_mpi_to_mpa(key->p, ltc_key.p);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_bignum_mpi_to_mpa(key->q, ltc_key.q);
	if (res != TEE_SUCCESS)
		goto err;
	res = copy_bignum_mpi_to_mpa(key->y, ltc_key.y);
	if (res != TEE_SUCCESS)
		goto err;
#endif

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);
	ltc_res = dsa_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, &ltc_key);
	mp_clear_multi(r, s, NULL);
	res = convert_ltc_verify_status(ltc_res, ltc_stat);
err:
#if defined(CFG_CRYPTO_MBEDTLS)
	dsa_free(&ltc_key);
#endif
	return res;
}

#endif /* CFG_CRYPTO_DSA */

#endif /* _CFG_CRYPTO_WITH_ACIPHER */

/******************************************************************************
 * Symmetric ciphers
 ******************************************************************************/

#if defined(_CFG_CRYPTO_WITH_CIPHER)
/* From libtomcrypt doc:
 *	Ciphertext stealing is a method of dealing with messages
 *	in CBC mode which are not a multiple of the block
 *	length.  This is accomplished by encrypting the last
 *	ciphertext block in ECB mode, and XOR'ing the output
 *	against the last partial block of plaintext. LibTomCrypt
 *	does not support this mode directly but it is fairly
 *	easy to emulate with a call to the cipher's
 *	ecb encrypt() callback function.
 *	The more sane way to deal with partial blocks is to pad
 *	them with zeroes, and then use CBC normally
 */

/*
 * From Global Platform: CTS = CBC-CS3
 */

#if defined(CFG_CRYPTO_CTS)
struct tee_symmetric_cts {
	symmetric_ECB ecb;
	symmetric_CBC cbc;
};
#endif

#if defined(CFG_CRYPTO_XTS)
#define XTS_TWEAK_SIZE 16
struct tee_symmetric_xts {
	symmetric_xts ctx;
	uint8_t tweak[XTS_TWEAK_SIZE];
};
#endif

static TEE_Result cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_AES)
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
		*size = sizeof(symmetric_ECB);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
		*size = sizeof(symmetric_CBC);
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		*size = sizeof(struct tee_symmetric_cts);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		*size = sizeof(struct tee_symmetric_xts);
		break;
#endif
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result crypto_cipher_lite_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	TEE_Result res;
	size_t ctx_size;
	void *ctx;

	res = cipher_get_ctx_size(algo, &ctx_size);
	if (res)
		return res;

	ctx = calloc(1, ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx_ret = ctx;
	return TEE_SUCCESS;
}

void crypto_cipher_lite_free_ctx(void *ctx, uint32_t algo __maybe_unused)
{
	size_t ctx_size __maybe_unused;

	/*
	 * Check that it's a supported algo, or crypto_cipher_alloc_ctx()
	 * could never have succeded above.
	 */
	assert(!cipher_get_ctx_size(algo, &ctx_size));
	free(ctx);
}

void crypto_cipher_lite_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	TEE_Result res __maybe_unused;
	size_t ctx_size = 0;

	res = cipher_get_ctx_size(algo, &ctx_size);
	assert(!res);
	memcpy(dst_ctx, src_ctx, ctx_size);
}

#if defined(CFG_CRYPTO_CBC_MAC)

static void get_des2_key(const uint8_t *key, size_t key_len,
			 uint8_t *key_intermediate,
			 uint8_t **real_key, size_t *real_key_len)
{
	if (key_len == 16) {
		/*
		 * This corresponds to a 2DES key. The 2DES encryption
		 * algorithm is similar to 3DES. Both perform and
		 * encryption step, then a decryption step, followed
		 * by another encryption step (EDE). However 2DES uses
		 * the same key for both of the encryption (E) steps.
		 */
		memcpy(key_intermediate, key, 16);
		memcpy(key_intermediate + 16, key, 8);
		*real_key = key_intermediate;
		*real_key_len = 24;
	} else {
		*real_key = (uint8_t *)key;
		*real_key_len = key_len;
	}
}

#endif

TEE_Result crypto_cipher_lite_init(void *ctx, uint32_t algo,
			      TEE_OperationMode mode __maybe_unused,
			      const uint8_t *key1, size_t key1_len,
			      const uint8_t *key2 __maybe_unused,
			      size_t key2_len __maybe_unused,
			      const uint8_t *iv __maybe_unused,
			      size_t iv_len __maybe_unused)
{
	TEE_Result res;
	int ltc_res, ltc_cipherindex;
#if defined(CFG_CRYPTO_CTS)
	struct tee_symmetric_cts *cts;
#endif
#if defined(CFG_CRYPTO_XTS)
	struct tee_symmetric_xts *xts;
#endif

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
		ltc_res = ecb_start(ltc_cipherindex, key1, key1_len,
				    0, (symmetric_ECB *)ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
		if (iv_len !=
		    (size_t)cipher_descriptor[ltc_cipherindex]->block_length)
			return TEE_ERROR_BAD_PARAMETERS;
		ltc_res = cbc_start(ltc_cipherindex, iv, key1, key1_len,
				    0, (symmetric_CBC *)ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		cts = ctx;
		res = crypto_cipher_lite_init((void *)(&(cts->ecb)),
					      TEE_ALG_AES_ECB_NOPAD, mode,
					      key1, key1_len, key2, key2_len,
					      iv, iv_len);
		if (res != TEE_SUCCESS)
			return res;
		res = crypto_cipher_lite_init((void *)(&(cts->cbc)),
					      TEE_ALG_AES_CBC_NOPAD, mode,
					      key1, key1_len, key2, key2_len,
					      iv, iv_len);
		if (res != TEE_SUCCESS)
			return res;
		ltc_res = CRYPT_OK;
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		xts = ctx;
		if (key1_len != key2_len)
			return TEE_ERROR_BAD_PARAMETERS;
		if (iv) {
			if (iv_len != XTS_TWEAK_SIZE)
				return TEE_ERROR_BAD_PARAMETERS;
			memcpy(xts->tweak, iv, iv_len);
		} else {
			memset(xts->tweak, 0, XTS_TWEAK_SIZE);
		}
		ltc_res = xts_start(ltc_cipherindex, key1, key2, key1_len,
				    0, &xts->ctx);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result crypto_cipher_lite_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode,
				bool last_block __maybe_unused,
				const uint8_t *data, size_t len, uint8_t *dst)
{
	int ltc_res = CRYPT_OK;
#if defined(CFG_CRYPTO_CTS)
	struct tee_symmetric_cts *cts;
#endif
#if defined(CFG_CRYPTO_XTS)
	struct tee_symmetric_xts *xts;
#endif

	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = ecb_encrypt(data, dst, len, ctx);
		else
			ltc_res = ecb_decrypt(data, dst, len, ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = cbc_encrypt(data, dst, len, ctx);
		else
			ltc_res = cbc_decrypt(data, dst, len, ctx);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		xts = ctx;
		if (mode == TEE_MODE_ENCRYPT)
			ltc_res = xts_encrypt(data, len, dst, xts->tweak,
					      &xts->ctx);
		else
			ltc_res = xts_decrypt(data, len, dst, xts->tweak,
					      &xts->ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		cts = ctx;
		return tee_aes_cbc_cts_update(&cts->cbc, &cts->ecb, mode,
					      last_block, data, len, dst);
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

void crypto_cipher_lite_final(void *ctx, uint32_t algo)
{
	switch (algo) {
#if defined(CFG_CRYPTO_ECB)
	case TEE_ALG_AES_ECB_NOPAD:
		ecb_done(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_CBC)
	case TEE_ALG_AES_CBC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc_done(ctx);
		break;
#endif
#if defined(CFG_CRYPTO_XTS)
	case TEE_ALG_AES_XTS:
		xts_done(&(((struct tee_symmetric_xts *)ctx)->ctx));
		break;
#endif
#if defined(CFG_CRYPTO_CTS)
	case TEE_ALG_AES_CTS:
		cbc_done(&(((struct tee_symmetric_cts *)ctx)->cbc));
		ecb_done(&(((struct tee_symmetric_cts *)ctx)->ecb));
		break;
#endif
	default:
		assert(!"Unhandled algo");
		break;
	}
}
#endif /* _CFG_CRYPTO_WITH_CIPHER */

/*****************************************************************************
 * Message Authentication Code functions
 *****************************************************************************/

#if defined(_CFG_CRYPTO_WITH_MAC)

#if defined(CFG_CRYPTO_CBC_MAC)
/*
 * CBC-MAC is not implemented in Libtomcrypt
 * This is implemented here as being the plain text which is encoded with IV=0.
 * Result of the CBC-MAC is the last 16-bytes cipher.
 */

#define CBCMAC_MAX_BLOCK_LEN 16
struct cbc_state {
	symmetric_CBC cbc;
	uint8_t block[CBCMAC_MAX_BLOCK_LEN];
	uint8_t digest[CBCMAC_MAX_BLOCK_LEN];
	size_t current_block_len, block_len;
	int is_computed;
};

static TEE_Result mac_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		*size = sizeof(struct cbc_state);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result crypto_cbc_mac_alloc_ctx(void **ctx_ret, uint32_t algo)
{
	TEE_Result res;
	size_t ctx_size;
	void *ctx;

	res = mac_get_ctx_size(algo, &ctx_size);
	if (res)
		return res;

	ctx = calloc(1, ctx_size);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*ctx_ret = ctx;
	return TEE_SUCCESS;
}

void crypto_cbc_mac_free_ctx(void *ctx, uint32_t algo __maybe_unused)
{
	size_t ctx_size __maybe_unused;

	/*
	 * Check that it's a supported algo, or crypto_mac_alloc_ctx()
	 * could never have succeded above.
	 */
	assert(!mac_get_ctx_size(algo, &ctx_size));
	free(ctx);
}

void crypto_cbc_mac_copy_state(void *dst_ctx, void *src_ctx, uint32_t algo)
{
	TEE_Result res __maybe_unused;
	size_t ctx_size = 0;

	res = mac_get_ctx_size(algo, &ctx_size);
	assert(!res);
	memcpy(dst_ctx, src_ctx, ctx_size);
}

TEE_Result crypto_cbc_mac_init(void *ctx, uint32_t algo, const uint8_t *key,
			   size_t len)
{
#if defined(CFG_CRYPTO_CBC_MAC)
	TEE_Result res;
	int ltc_cipherindex;
	uint8_t *real_key;
	uint8_t key_array[24];
	size_t real_key_len;
	uint8_t iv[CBCMAC_MAX_BLOCK_LEN];
	struct cbc_state *cbc;
#endif

	switch (algo) {
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

		res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
		if (res != TEE_SUCCESS)
			return res;

		cbc->block_len =
			cipher_descriptor[ltc_cipherindex]->block_length;
		if (cbc->block_len > CBCMAC_MAX_BLOCK_LEN)
			return TEE_ERROR_BAD_PARAMETERS;
		memset(iv, 0, cbc->block_len);

		if (algo == TEE_ALG_DES3_CBC_MAC_NOPAD ||
		    algo == TEE_ALG_DES3_CBC_MAC_PKCS5) {
			get_des2_key(key, len, key_array,
				     &real_key, &real_key_len);
			key = real_key;
			len = real_key_len;
		}
		if (cbc_start(ltc_cipherindex, iv, key, len,
			      0, &cbc->cbc) != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		cbc->is_computed = 0;
		cbc->current_block_len = 0;
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result crypto_cbc_mac_update(void *ctx, uint32_t algo, const uint8_t *data,
			     size_t len)
{
#if defined(CFG_CRYPTO_CBC_MAC)
	int ltc_res;
	struct cbc_state *cbc;
	size_t pad_len;
#endif

	if (!data || !len)
		return TEE_SUCCESS;

	switch (algo) {
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = ctx;

		if ((cbc->current_block_len > 0) &&
		    (len + cbc->current_block_len >= cbc->block_len)) {
			pad_len = cbc->block_len - cbc->current_block_len;
			memcpy(cbc->block + cbc->current_block_len,
			       data, pad_len);
			data += pad_len;
			len -= pad_len;
			ltc_res = cbc_encrypt(cbc->block, cbc->digest,
					      cbc->block_len, &cbc->cbc);
			if (ltc_res != CRYPT_OK)
				return TEE_ERROR_BAD_STATE;
			cbc->is_computed = 1;
		}

		while (len >= cbc->block_len) {
			ltc_res = cbc_encrypt(data, cbc->digest,
					      cbc->block_len, &cbc->cbc);
			if (ltc_res != CRYPT_OK)
				return TEE_ERROR_BAD_STATE;
			cbc->is_computed = 1;
			data += cbc->block_len;
			len -= cbc->block_len;
		}

		if (len > 0)
			memcpy(cbc->block, data, len);
		cbc->current_block_len = len;
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result crypto_cbc_mac_final(void *ctx, uint32_t algo, uint8_t *digest,
			    size_t digest_len)
{
#if defined(CFG_CRYPTO_CBC_MAC)
	struct cbc_state *cbc;
	size_t pad_len;
	unsigned long ltc_digest_len = digest_len;
#endif

	switch (algo) {
#if defined(CFG_CRYPTO_CBC_MAC)
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

		/* Padding is required */
		switch (algo) {
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			/*
			 * Padding is in whole bytes. The value of each added
			 * byte is the number of bytes that are added, i.e. N
			 * bytes, each of value N are added
			 */
			pad_len = cbc->block_len - cbc->current_block_len;
			memset(cbc->block+cbc->current_block_len,
			       pad_len, pad_len);
			cbc->current_block_len = 0;
			if (crypto_cbc_mac_update(ctx, algo, cbc->block,
						  cbc->block_len) !=
						  TEE_SUCCESS)
				return TEE_ERROR_BAD_STATE;
			break;
		default:
			/* nothing to do */
			break;
		}

		if ((!cbc->is_computed) || (cbc->current_block_len != 0))
			return TEE_ERROR_BAD_STATE;

		memcpy(digest, cbc->digest,
		       MIN(ltc_digest_len, cbc->block_len));
		crypto_cipher_lite_final(&cbc->cbc, algo);
		break;
#endif
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}
#endif /* _CFG_CRYPTO_WITH_MAC */
#endif

TEE_Result crypto_lite_init(void)
{
#if defined(_CFG_CRYPTO_WITH_ACIPHER)
	tee_ltc_alloc_mpa();
#endif
	tee_ltc_reg_algs();

	return TEE_SUCCESS;
}

#if defined(CFG_WITH_VFP)
void tomcrypt_arm_neon_enable(struct tomcrypt_arm_neon_state *state)
{
	state->state = thread_kernel_enable_vfp();
}

void tomcrypt_arm_neon_disable(struct tomcrypt_arm_neon_state *state)
{
	thread_kernel_disable_vfp(state->state);
}
#endif
