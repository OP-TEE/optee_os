// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021, 2023 NXP
 *
 * CAAM RSA manager.
 * Implementation of RSA functions
 */
#include <caam_acipher.h>
#include <caam_common.h>
#include <caam_desc_helper.h>
#include <caam_hal_ctrl.h>
#include <caam_io.h>
#include <caam_jr.h>
#include <caam_key.h>
#include <caam_status.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <drvcrypt_math.h>
#include <mm/core_memprot.h>
#include <stdint.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <utee_types.h>

#include "local.h"

/*
 * Definition of the maximum bits of Exponent e
 * Refer to sp800-56b
 */
#define MAX_BITS_EXP_E 256

/*
 * Define the maximum number of entries in a descriptor
 * function of the encrypt/decrypt and private key format
 */
#ifdef CFG_CAAM_64BIT
#define MAX_DESC_ENC   (8 + 4)
#define MAX_DESC_DEC_1 (7 + 2 + 4)
#define MAX_DESC_DEC_2 (11 + 2 + 7)
#define MAX_DESC_DEC_3 (13 + 2 + 10)
/* Define the maximum number of entries in the RSA Finish Key descriptor */
#define MAX_DESC_KEY_FINISH 24
#else
#define MAX_DESC_ENC	    8
#define MAX_DESC_DEC_1	    (7 + 2)
#define MAX_DESC_DEC_2	    (11 + 2)
#define MAX_DESC_DEC_3	    (13 + 2)
/* Define the maximum number of entries in the RSA Finish Key descriptor */
#define MAX_DESC_KEY_FINISH 15
#endif /* CFG_CAAM_64BIT */

static TEE_Result do_caam_encrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation);
static TEE_Result do_caam_decrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation);

/*
 * Definition of the local RSA keypair
 *   Public Key Format: (n, e)
 *   Private Key Format #1: (n, d)
 *   Private Key Format #2: (p, q, d)
 *   Private Key Format #3: (p, q, dp, dq, qp)
 */
struct caam_rsa_keypair {
	uint8_t format;	    /* Define the Private Key Format (1, 2 or 3) */
	struct caambuf n;   /* Modulus [n = p * q] */
	struct caambuf e;   /* Public Exponent 65537 <= e < 2^256 */
	struct caamkey d;   /* Private Exponent [d = 1/e mod LCM(p-1, q-1)] */
	struct caamkey p;   /* Private Prime p */
	struct caamkey q;   /* Private Prime q */
	struct caamkey dp;  /* Private [dp = d mod (p-1)] */
	struct caamkey dq;  /* Private [dq = d mod (q-1)] */
	struct caamkey qp;  /* Private [qp = 1/q mod p] */
};

#define RSA_PRIVATE_KEY_FORMAT_1 1
#define RSA_PRIVATE_KEY_FORMAT_2 2
#define RSA_PRIVATE_KEY_FORMAT_3 3

/* CAAM Era version */
static uint8_t caam_era;

/*
 * Free RSA keypair
 *
 * @key  RSA keypair
 */
static void do_free_keypair(struct rsa_keypair *key)
{
	crypto_bignum_free(&key->e);
	crypto_bignum_free(&key->d);
	crypto_bignum_free(&key->n);
	crypto_bignum_free(&key->p);
	crypto_bignum_free(&key->q);
	crypto_bignum_free(&key->qp);
	crypto_bignum_free(&key->dp);
	crypto_bignum_free(&key->dq);
}

/*
 * Free local caam RSA keypair
 *
 * @key  caam RSA keypair
 */
static void do_keypair_free(struct caam_rsa_keypair *key)
{
	caam_free_buf(&key->e);
	caam_free_buf(&key->n);

	caam_key_free(&key->d);
	caam_key_free(&key->p);
	caam_key_free(&key->q);
	caam_key_free(&key->dp);
	caam_key_free(&key->dq);
	caam_key_free(&key->qp);
}

/*
 * Convert Crypto RSA Key to local RSA Public Key
 * Ensure Key is push in physical memory
 *
 * @outkey   [out] Output keypair in local format
 * @inkey    Input key in TEE Crypto format
 */
static enum caam_status do_keypub_conv(struct caam_rsa_keypair *outkey,
				       const struct rsa_public_key *inkey)
{
	enum caam_status retstatus = CAAM_FAILURE;

	RSA_TRACE("RSA Convert Public Key size N=%zu",
		  crypto_bignum_num_bytes(inkey->n));

	retstatus = caam_calloc_align_buf(&outkey->e,
					  crypto_bignum_num_bytes(inkey->e));
	if (retstatus != CAAM_NO_ERROR)
		goto exit_conv;

	crypto_bignum_bn2bin(inkey->e, outkey->e.data);
	cache_operation(TEE_CACHECLEAN, outkey->e.data, outkey->e.length);

	retstatus = caam_calloc_align_buf(&outkey->n,
					  crypto_bignum_num_bytes(inkey->n));
	if (retstatus != CAAM_NO_ERROR)
		goto exit_conv;

	crypto_bignum_bn2bin(inkey->n, outkey->n.data);
	cache_operation(TEE_CACHECLEAN, outkey->n.data, outkey->n.length);

	return CAAM_NO_ERROR;

exit_conv:
	do_keypair_free(outkey);

	return CAAM_OUT_MEMORY;
}

/*
 * Convert Crypto RSA Key additional fields of the key format #3
 * Optional fields (dp, dq, qp)
 *
 * @outkey   [out] Output keypair in local format
 * @inkey    Input key in TEE Crypto format
 */
static enum caam_status do_keypair_conv_f3(struct caam_rsa_keypair *outkey,
					   const struct rsa_keypair *inkey)
{
	enum caam_status retstatus = CAAM_FAILURE;
	size_t size_p = 0;
	size_t size_q = 0;
	size_t size_dp = 0;
	size_t size_dq = 0;
	size_t size_qp = 0;

	size_p = outkey->p.sec_size;
	size_q = outkey->q.sec_size;
	size_dp = crypto_bignum_num_bytes(inkey->dp);
	size_dq = crypto_bignum_num_bytes(inkey->dq);
	size_qp = crypto_bignum_num_bytes(inkey->qp);

	/*
	 * If one of the parameters dp, dq or qp are not filled,
	 * returns immediately. This is not an error.
	 */
	if (!size_dp || !size_dq || !size_qp)
		return CAAM_NO_ERROR;

	/*
	 * CAAM is assuming that:
	 *    - dp and dq are same size as p
	 *    - dq same size as q
	 *
	 * Because calculation of dp, dq and qp can be less
	 * than above assumption, force the dp, dq and qp
	 * buffer size.
	 */
	retstatus = caam_key_deserialize_from_bn(inkey->dp,
						 &outkey->dp, size_p);
	if (retstatus)
		return retstatus;

	/* Field dq */
	retstatus = caam_key_deserialize_from_bn(inkey->dq,
						 &outkey->dq, size_p);
	if (retstatus)
		return retstatus;

	/* Field qp */
	retstatus = caam_key_deserialize_from_bn(inkey->qp,
						 &outkey->qp, size_q);
	if (retstatus)
		return retstatus;

	/* Push fields value to the physical memory */
	caam_key_cache_op(TEE_CACHECLEAN, &outkey->dp);
	caam_key_cache_op(TEE_CACHECLEAN, &outkey->qp);
	caam_key_cache_op(TEE_CACHECLEAN, &outkey->dq);

	outkey->format = RSA_PRIVATE_KEY_FORMAT_3;

	return CAAM_NO_ERROR;
}

/*
 * Convert Crypto RSA Key additional fields of the key format #2
 * Optional fields (p, q)
 *
 * @outkey   [out] Output keypair in local format
 * @inkey    Input key in TEE Crypto format
 */
static enum caam_status do_keypair_conv_f2(struct caam_rsa_keypair *outkey,
					   const struct rsa_keypair *inkey)
{
	enum caam_status retstatus = CAAM_FAILURE;
	size_t size_p = 0;
	size_t size_q = 0;

	size_p = crypto_bignum_num_bytes(inkey->p);
	size_q = crypto_bignum_num_bytes(inkey->q);

	/*
	 * If the Prime P or Prime Q are not filled, returns
	 * immediately. This is not an error.
	 */
	if (size_p || !size_q)
		return CAAM_NO_ERROR;

	/* Field Prime p */
	retstatus = caam_key_deserialize_from_bn(inkey->p, &outkey->p, 0);
	if (retstatus)
		return retstatus;

	/* Field Prime q */
	retstatus = caam_key_deserialize_from_bn(inkey->q, &outkey->q, 0);
	if (retstatus)
		return retstatus;

	/* Push fields value to the physical memory */
	caam_key_cache_op(TEE_CACHECLEAN, &outkey->p);
	caam_key_cache_op(TEE_CACHECLEAN, &outkey->q);

	outkey->format = RSA_PRIVATE_KEY_FORMAT_2;

	if (CFG_NXP_CAAM_RSA_KEY_FORMAT > RSA_PRIVATE_KEY_FORMAT_2) {
		retstatus = do_keypair_conv_f3(outkey, inkey);
		RSA_TRACE("do_keypair_conv_f3 returned 0x%" PRIx32, retstatus);
	}

	return retstatus;
}

/*
 * Convert Crypto RSA Key to local RSA Keypair Key
 * Ensure Key is push in physical memory
 * Don't convert the exponent e not used in decrytion
 *
 * @outkey   [out] Output keypair in local format
 * @inkey    Input key in TEE Crypto format
 */
static enum caam_status do_keypair_conv(struct caam_rsa_keypair *outkey,
					const struct rsa_keypair *inkey)
{
	enum caam_status retstatus = CAAM_FAILURE;

	RSA_TRACE("RSA Convert Keypair size N=%zu",
		  crypto_bignum_num_bytes(inkey->n));

	/* Mandatory fields are n and d => Private Key Format #1 */
	retstatus = caam_calloc_align_buf(&outkey->n,
					  crypto_bignum_num_bytes(inkey->n));
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	crypto_bignum_bn2bin(inkey->n, outkey->n.data);
	cache_operation(TEE_CACHECLEAN, outkey->n.data, outkey->n.length);

	retstatus = caam_key_deserialize_from_bn(inkey->d, &outkey->d, 0);
	if (retstatus)
		return retstatus;

	caam_key_cache_op(TEE_CACHECLEAN, &outkey->d);

	outkey->format = RSA_PRIVATE_KEY_FORMAT_1;

	if (CFG_NXP_CAAM_RSA_KEY_FORMAT > RSA_PRIVATE_KEY_FORMAT_1) {
		retstatus = do_keypair_conv_f2(outkey, inkey);
		RSA_TRACE("do_keypair_conv_f2 returned 0x%" PRIx32, retstatus);
	}

	return retstatus;
}

/*
 * Allocate a RSA keypair
 *
 * @key        Keypair
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_keypair(struct rsa_keypair *key,
				      size_t size_bits)
{
	RSA_TRACE("Allocate Keypair of %zu bits", size_bits);

	/* Initialize all input key fields to 0 */
	memset(key, 0, sizeof(*key));

	/* Allocate the Public Exponent to maximum size */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_keypair;

	/* Allocate the Private Exponent [d = 1/e mod LCM(p-1, q-1)] */
	key->d = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);
	if (!key->d)
		goto err_alloc_keypair;

	/* Allocate the Modulus (size_bits) [n = p * q] */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_keypair;

	/* Allocate the prime number p of size (size_bits / 2) */
	key->p = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);
	if (!key->p)
		goto err_alloc_keypair;

	/* Allocate the prime number q of size (size_bits / 2) */
	key->q = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);
	if (!key->q)
		goto err_alloc_keypair;

	/* Allocate dp (size_bits / 2) [d mod (p-1)] */
	key->dp = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);
	if (!key->dp)
		goto err_alloc_keypair;

	/* Allocate dq (size_bits / 2) [d mod (q-1)] */
	key->dq = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);
	if (!key->dq)
		goto err_alloc_keypair;

	/* Allocate qp (size_bits / 2) [1/q mod p] */
	key->qp = crypto_bignum_allocate(CFG_CORE_BIGNUM_MAX_BITS);
	if (!key->qp)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	RSA_TRACE("Allocation error");

	do_free_keypair(key);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Allocate a RSA public key
 *
 * @key        Public Key
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_publickey(struct rsa_public_key *key,
					size_t size_bits)
{
	RSA_TRACE("Allocate Public Key of %zu bits", size_bits);

	/* Initialize all input key fields to 0 */
	memset(key, 0, sizeof(*key));

	/* Allocate the Public Exponent to maximum size */
	key->e = crypto_bignum_allocate(MAX_BITS_EXP_E);
	if (!key->e)
		goto err_alloc_publickey;

	/* Allocate the Modulus (size_bits) [n = p * q] */
	key->n = crypto_bignum_allocate(size_bits);
	if (!key->n)
		goto err_alloc_publickey;

	return TEE_SUCCESS;

err_alloc_publickey:
	RSA_TRACE("Allocation error");

	crypto_bignum_free(&key->e);
	crypto_bignum_free(&key->n);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Free a RSA public key
 *
 * @key        Public Key
 */
static void do_free_publickey(struct rsa_public_key *key)
{
	crypto_bignum_free(&key->e);
	crypto_bignum_free(&key->n);
}

/*
 * Output the RSA keypair format 3 additional fields in bignumber object
 *
 * @key        [out] Keypair
 * @key_size   Key size in bits
 */
static TEE_Result gen_keypair_get_f3(struct rsa_keypair *key,
				     struct caam_rsa_keypair *genkey)
{
	enum caam_status status = CAAM_FAILURE;

	caam_key_cache_op(TEE_CACHEINVALIDATE, &genkey->dp);
	caam_key_cache_op(TEE_CACHEINVALIDATE, &genkey->dq);
	caam_key_cache_op(TEE_CACHEINVALIDATE, &genkey->qp);

	RSA_DUMPBUF("dp", genkey->dp.buf.data, genkey->dp.buf.length);
	RSA_DUMPBUF("dq", genkey->dq.buf.data, genkey->dq.buf.length);
	RSA_DUMPBUF("qp", genkey->qp.buf.data, genkey->qp.buf.length);

	status = caam_key_serialize_to_bn(key->dp, &genkey->dp);
	if (status)
		return caam_status_to_tee_result(status);

	status = caam_key_serialize_to_bn(key->dq, &genkey->dq);
	if (status)
		return caam_status_to_tee_result(status);

	status = caam_key_serialize_to_bn(key->qp, &genkey->qp);
	if (status)
		return caam_status_to_tee_result(status);

	return TEE_SUCCESS;
}

/*
 * Output the RSA keypair format 2 additional fields in big number object
 *
 * @key        [out] Keypair
 * @key_size   Key size in bits
 */
static TEE_Result gen_keypair_get_f2(struct rsa_keypair *key,
				     struct caam_rsa_keypair *genkey)
{
	enum caam_status status = CAAM_FAILURE;

	caam_key_cache_op(TEE_CACHEINVALIDATE, &genkey->q);
	caam_key_cache_op(TEE_CACHEINVALIDATE, &genkey->p);

	RSA_DUMPBUF("p", genkey->p.buf.data, genkey->p.buf.length);
	RSA_DUMPBUF("q", genkey->q.buf.data, genkey->q.buf.length);

	status = caam_key_serialize_to_bn(key->p, &genkey->p);
	if (status)
		return caam_status_to_tee_result(status);

	status = caam_key_serialize_to_bn(key->q, &genkey->q);
	if (status)
		return caam_status_to_tee_result(status);

	if (genkey->format > RSA_PRIVATE_KEY_FORMAT_2)
		return gen_keypair_get_f3(key, genkey);

	return TEE_SUCCESS;
}

static TEE_Result
do_black_key_encapsulation(struct caam_rsa_keypair *rsa_keypair)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_key_type key_type = caam_key_default_key_gen_type();

	ret = caam_key_black_encapsulation(&rsa_keypair->p, key_type);
	if (ret) {
		RSA_TRACE("RSA Key p component encapsulation failed");
		return ret;
	}

	ret = caam_key_black_encapsulation(&rsa_keypair->q, key_type);
	if (ret) {
		RSA_TRACE("RSA Key q component encapsulation failed");
		return ret;
	}

	RSA_TRACE("Black key encapsulation done");

	return TEE_SUCCESS;
}

/*
 * Generates a RSA keypair
 *
 * @key        [out] Keypair
 * @key_size   Key size in bits
 */
static TEE_Result do_gen_keypair(struct rsa_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_rsa_keypair genkey = { };
	size_t size_d_gen __maybe_unused = 0;
	uint32_t *size_d_gen_val_ptr = NULL;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = 0;
	uint32_t desclen = 0;
	struct prime_data_rsa prime = { };
	enum caam_key_type key_type = caam_key_default_key_gen_type();
	size_t key_size_bytes = key_size / 8;

	RSA_TRACE("Generate Keypair of %zu bits", key_size);

	genkey.format = CFG_NXP_CAAM_RSA_KEY_FORMAT;

	/* Allocate the job used to prepare the operation */
	desc = caam_calloc_desc(MAX_DESC_KEY_FINISH);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	size_d_gen_val_ptr = caam_calloc_align(sizeof(uint32_t));
	if (!size_d_gen_val_ptr) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/* First allocate primes p and q */
	genkey.p.key_type = CAAM_KEY_PLAIN_TEXT;
	genkey.p.sec_size = key_size_bytes / 2;
	genkey.p.is_blob = false;

	retstatus = caam_key_alloc(&genkey.p);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_gen_keypair;
	}

	genkey.q.key_type = CAAM_KEY_PLAIN_TEXT;
	genkey.q.sec_size = key_size_bytes / 2;
	genkey.q.is_blob = false;

	retstatus = caam_key_alloc(&genkey.q);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_gen_keypair;
	}

	/* Allocate Public exponent to a caam buffer */
	retstatus = caam_calloc_buf(&genkey.e, crypto_bignum_num_bytes(key->e));
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_gen_keypair;
	}

	genkey.d.key_type = key_type;
	genkey.d.sec_size = key_size_bytes;
	genkey.d.is_blob = false;

	retstatus = caam_key_alloc(&genkey.d);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_gen_keypair;
	}

	retstatus = caam_calloc_align_buf(&genkey.n, key_size_bytes);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_gen_keypair;
	}

	if (genkey.format > RSA_PRIVATE_KEY_FORMAT_2) {
		genkey.dp.key_type = key_type;
		genkey.dp.sec_size = key_size_bytes / 2;
		genkey.dp.is_blob = false;

		retstatus = caam_key_alloc(&genkey.dp);
		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto exit_gen_keypair;
		}

		genkey.dq.key_type = key_type;
		genkey.dq.sec_size = key_size_bytes / 2;
		genkey.dq.is_blob = false;

		retstatus = caam_key_alloc(&genkey.dq);
		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto exit_gen_keypair;
		}

		genkey.qp.key_type = key_type;
		genkey.qp.sec_size = key_size_bytes / 2;
		genkey.qp.is_blob = false;

		retstatus = caam_key_alloc(&genkey.qp);
		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto exit_gen_keypair;
		}
	}

	crypto_bignum_bn2bin(key->e, genkey.e.data);

	prime.era = caam_era;
	prime.key_size = key_size;
	prime.e = &genkey.e;
	prime.p = &genkey.p.buf;
	prime.q = &genkey.q.buf;

	/* Generate prime p and q */
	retstatus = caam_prime_rsa_gen(&prime);
	RSA_TRACE("Generate Prime P and Q returned 0x%" PRIx32, retstatus);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_gen_keypair;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	caam_desc_add_word(desc, 0);
	caam_desc_add_word(desc, PDB_RSA_KEY_P_SIZE(genkey.p.sec_size));
	caam_desc_add_word(desc, PDB_RSA_KEY_N_SIZE(genkey.n.length) |
					 PDB_RSA_KEY_E_SIZE(genkey.e.length));

	caam_desc_add_ptr(desc, genkey.p.buf.paddr);
	caam_desc_add_ptr(desc, genkey.q.buf.paddr);
	caam_desc_add_ptr(desc, genkey.e.paddr);
	caam_desc_add_ptr(desc, genkey.n.paddr);
	caam_desc_add_ptr(desc, genkey.d.buf.paddr);
	caam_desc_add_ptr(desc, virt_to_phys(size_d_gen_val_ptr));

	if (genkey.format > RSA_PRIVATE_KEY_FORMAT_2) {
		caam_desc_add_ptr(desc, genkey.dp.buf.paddr);
		caam_desc_add_ptr(desc, genkey.dq.buf.paddr);
		caam_desc_add_ptr(desc, genkey.qp.buf.paddr);

		switch (key_type) {
		case CAAM_KEY_PLAIN_TEXT:
			caam_desc_add_word(desc, RSA_FINAL_KEY(ALL, NONE));
			break;
		case CAAM_KEY_BLACK_ECB:
			caam_desc_add_word(desc, RSA_FINAL_KEY(ALL, ECB));
			break;
		case CAAM_KEY_BLACK_CCM:
			caam_desc_add_word(desc, RSA_FINAL_KEY(ALL, CCM));
			break;
		default:
			ret = TEE_ERROR_GENERIC;
			goto exit_gen_keypair;
		}

		caam_key_cache_op(TEE_CACHEFLUSH, &genkey.dp);
		caam_key_cache_op(TEE_CACHEFLUSH, &genkey.dq);
		caam_key_cache_op(TEE_CACHEFLUSH, &genkey.qp);
	} else {
		switch (key_type) {
		case CAAM_KEY_PLAIN_TEXT:
			caam_desc_add_word(desc, RSA_FINAL_KEY(N_D, NONE));
			break;
		case CAAM_KEY_BLACK_ECB:
			caam_desc_add_word(desc, RSA_FINAL_KEY(N_D, ECB));
			break;
		case CAAM_KEY_BLACK_CCM:
			caam_desc_add_word(desc, RSA_FINAL_KEY(N_D, CCM));
			break;
		default:
			ret = TEE_ERROR_GENERIC;
			goto exit_gen_keypair;
		}
	}

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	jobctx.desc = desc;
	RSA_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, genkey.e.data, genkey.e.length);
	caam_key_cache_op(TEE_CACHEFLUSH, &genkey.p);
	caam_key_cache_op(TEE_CACHEFLUSH, &genkey.q);
	caam_key_cache_op(TEE_CACHEFLUSH, &genkey.d);
	cache_operation(TEE_CACHEFLUSH, genkey.n.data, genkey.n.length);
	cache_operation(TEE_CACHEFLUSH, size_d_gen_val_ptr, sizeof(uint32_t));

	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		caam_key_cache_op(TEE_CACHEINVALIDATE, &genkey.d);
		cache_operation(TEE_CACHEINVALIDATE, &genkey.n,
				genkey.n.length);

		cache_operation(TEE_CACHEINVALIDATE, size_d_gen_val_ptr,
				sizeof(uint32_t));

		size_d_gen = caam_read_val32(size_d_gen_val_ptr);

		RSA_TRACE("D size %zu", size_d_gen);
		RSA_DUMPBUF("D", genkey.d.buf.data, genkey.d.buf.length);
		RSA_DUMPBUF("N", genkey.n.data, genkey.n.length);

		genkey.d.sec_size = size_d_gen;

		if (key_type != CAAM_KEY_PLAIN_TEXT) {
			ret = do_black_key_encapsulation(&genkey);
			if (ret != TEE_SUCCESS)
				goto exit_gen_keypair;
		}

		ret = crypto_bignum_bin2bn(genkey.n.data, genkey.n.length,
					   key->n);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		retstatus = caam_key_serialize_to_bn(key->d, &genkey.d);
		if (retstatus) {
			ret = caam_status_to_tee_result(retstatus);
			goto exit_gen_keypair;
		}

		if (genkey.format > RSA_PRIVATE_KEY_FORMAT_1)
			ret = gen_keypair_get_f2(key, &genkey);
	} else {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_gen_keypair:
	do_keypair_free(&genkey);
	caam_free(size_d_gen_val_ptr);
	caam_free_desc(&desc);

	return ret;
}

/*
 * RSA EME-OAEP Decoding operation
 * Refer the chapter 7.1.2 Decryption operation of pkcs-1v2-1 specification
 *
 * @rsa_data  [in/out] RSA Data to encode
 */
static TEE_Result do_oaep_decoding(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caambuf DB = { };
	struct caambuf lHash = { };
	struct caambuf seed = { };
	struct caambuf dbMask = { };
	struct caambuf maskedDB = { };
	struct caambuf maskedSeed = { };
	struct caambuf EM = { };
	size_t db_size = 0;
	size_t b01_idx = 0;
	size_t db_len = 0;
	struct drvcrypt_rsa_mgf mgf_data = { };
	struct drvcrypt_rsa_ed dec_data = { };
	struct drvcrypt_mod_op mod_op = { };

	RSA_TRACE("RSA OAEP Decoding");

	/*
	 * First Decryption of the Cipher to a EM of modulus size
	 */
	retstatus = caam_calloc_align_buf(&EM, rsa_data->key.n_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_decrypt;
	}

	memcpy(&dec_data, rsa_data, sizeof(dec_data));
	dec_data.message.data = EM.data;
	dec_data.message.length = EM.length;

	ret = do_caam_decrypt(&dec_data, RSA_DECRYPT(NO));

	RSA_DUMPBUF("EM", EM.data, EM.length);

	/*
	 * DB = lHash' || PS || 0x01 || M
	 * DB length = k - hLen - 1
	 *
	 * PS is a 0's buffer of length h - mLen - 2hLen - 2
	 *
	 *  k    is the key modulus length
	 *  hLen is the Hash digest length
	 *  mLen is the input RSA message length
	 */
	/* Calculate the DB size */
	db_size = rsa_data->key.n_size - rsa_data->digest_size - 1;
	RSA_TRACE("DB is %zu bytes", db_size);

	/* Allocate the DB buffer */
	retstatus = caam_calloc_align_buf(&DB, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_decrypt;
	}

	/*
	 * Step a
	 * Generate the lHash
	 */
	/* Allocate the lHash buffer */
	retstatus = caam_calloc_align_buf(&lHash, rsa_data->digest_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_decrypt;
	}

	RSA_TRACE("Hash the RSA Label of %zu bytes", rsa_data->label.length);
	ret = tee_hash_createdigest(rsa_data->hash_algo, rsa_data->label.data,
				    rsa_data->label.length, lHash.data,
				    lHash.length);
	RSA_TRACE("Hash the RSA Label returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_decrypt;

	RSA_DUMPBUF("lHash", lHash.data, lHash.length);

	/* Allocate the seed buffer */
	retstatus = caam_calloc_align_buf(&seed, rsa_data->digest_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_decrypt;
	}

	/* Allocate the dbMask buffer */
	retstatus = caam_calloc_align_buf(&dbMask, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_decrypt;
	}

	/*
	 * Step b
	 * Split the EM string
	 * EM = Y || maskedSeed || maskedDB
	 *
	 * Where:
	 *   Y          size = 1 byte
	 *   maskedSeed size = hLen
	 *   maskedDB   size = k - hLen - 1 bytes
	 *
	 *  k    is the key modulus length
	 *  hLen is the Hash digest length
	 *  mLen is the input RSA message length
	 *
	 *  Note Y should have been remove during the
	 */
	maskedSeed.data = &EM.data[1];
	maskedSeed.length = rsa_data->digest_size;
	maskedSeed.paddr = EM.paddr + sizeof(uint8_t);

	maskedDB.data = &EM.data[1 + rsa_data->digest_size];
	maskedDB.length = dbMask.length;
	maskedDB.paddr = EM.paddr + sizeof(uint8_t) + rsa_data->digest_size;

	/*
	 * Step c
	 * Generate a Mask of the maskedDB
	 * seedMask = MGF(maskedDB, k - hLen - 1)
	 *
	 * Note: Use same buffer for seed and seedMask
	 */
	mgf_data.hash_algo = rsa_data->hash_algo;
	mgf_data.digest_size = rsa_data->digest_size;
	mgf_data.seed.data = maskedDB.data;
	mgf_data.seed.length = maskedDB.length;
	mgf_data.mask.data = seed.data;
	mgf_data.mask.length = seed.length;

	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_decrypt;

	/*
	 * Step d
	 * seed = maskedSeed xor seedMask
	 *
	 * Note: Use same buffer for seed and seedMask
	 */
	mod_op.n.length = seed.length;
	mod_op.a.data = maskedSeed.data;
	mod_op.a.length = maskedSeed.length;
	mod_op.b.data = seed.data;
	mod_op.b.length = seed.length;
	mod_op.result.data = seed.data;
	mod_op.result.length = seed.length;

	retstatus = drvcrypt_xor_mod_n(&mod_op);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_decrypt;
	}

	RSA_DUMPBUF("Seed", seed.data, seed.length);

	/*
	 * Step e
	 * Generate a Mask of the seed value
	 * dbMask = MGF(seed, k - hLen - 1)
	 */
	mgf_data.seed.data = seed.data;
	mgf_data.seed.length = seed.length;
	mgf_data.mask.data = dbMask.data;
	mgf_data.mask.length = dbMask.length;

	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_decrypt;

	/*
	 * Step f
	 * DB = maskedDB xor dbMask
	 */
	mod_op.n.length = DB.length;
	mod_op.a.data = maskedDB.data;
	mod_op.a.length = maskedDB.length;
	mod_op.b.data = dbMask.data;
	mod_op.b.length = dbMask.length;
	mod_op.result.data = DB.data;
	mod_op.result.length = DB.length;

	retstatus = drvcrypt_xor_mod_n(&mod_op);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_decrypt;
	}

	RSA_DUMPBUF("DB", DB.data, DB.length);

	/*
	 * Step g
	 * Check the DB generated
	 * DB = lHash' || PS || 0x01 || M
	 *
	 * Error if:
	 *   - lHash' != lHash (First step - Hash the Label)
	 *   - byte 0x01 between PS and M is not present
	 */
	/* Check Hash values */
	if (memcmp(DB.data, lHash.data, lHash.length)) {
		RSA_TRACE("Hash error");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_oaep_decrypt;
	}

	/* Find the byte 0x01 separating PS and M */
	for (b01_idx = rsa_data->digest_size;
	     b01_idx < db_size && !DB.data[b01_idx]; b01_idx++)
		;

	if (b01_idx == db_size) {
		RSA_TRACE("byte 0x01 not present");
		ret = TEE_ERROR_BAD_PARAMETERS;
		goto exit_oaep_decrypt;
	}

	db_len = DB.length - b01_idx - 1;

	if (rsa_data->message.length < db_len) {
		rsa_data->message.length = db_len;
		ret = TEE_ERROR_SHORT_BUFFER;
		goto exit_oaep_decrypt;
	}

	rsa_data->message.length = db_len;
	memcpy(rsa_data->message.data, &DB.data[b01_idx + 1],
	       rsa_data->message.length);

	RSA_DUMPBUF("Message decrypted", rsa_data->message.data,
		    rsa_data->message.length);
	ret = TEE_SUCCESS;

exit_oaep_decrypt:
	caam_free_buf(&EM);
	caam_free_buf(&DB);
	caam_free_buf(&seed);
	caam_free_buf(&dbMask);
	caam_free_buf(&lHash);

	return ret;
}

/*
 * RSA EME-OAEP Encoding operation
 * Refer the chapter 7.1.1 Encryption operation of pkcs-1v2-1 specification
 *
 * @rsa_data  [int/out] RSA Data to encode
 */
static TEE_Result do_oaep_encoding(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus;
	struct caambuf DB = { };
	struct caambuf lHash = { };
	struct caambuf seed = { };
	struct caambuf dbMask = { };
	struct caambuf maskedDB = { };
	struct caambuf maskedSeed = { };
	struct caambuf EM = { };
	size_t db_size = 0;
	size_t ps_size = 0;
	struct drvcrypt_rsa_mgf mgf_data = { };
	struct drvcrypt_rsa_ed enc_data = { };
	struct drvcrypt_mod_op mod_op = { };

	RSA_TRACE("RSA OAEP Encoding");

	/*
	 * DB = lHash || PS || 0x01 || M
	 * DB length = k - hLen - 1
	 *
	 * PS is a 0's buffer of length h - mLen - 2hLen - 2
	 *
	 *  k    is the key modulus length
	 *  hLen is the Hash digest length
	 *  mLen is the input RSA message length
	 */
	/* Calculate the DB size */
	db_size = rsa_data->key.n_size - rsa_data->digest_size - 1;
	RSA_TRACE("DB is %zu bytes", db_size);

	/* Allocate the DB buffer */
	retstatus = caam_calloc_align_buf(&DB, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_encrypt;
	}

	/*
	 * Step a
	 * Generate the lHash
	 */
	lHash.length = rsa_data->digest_size;
	lHash.data = DB.data;

	RSA_TRACE("Hash the RSA Label of %zu bytes", rsa_data->label.length);
	ret = tee_hash_createdigest(rsa_data->hash_algo, rsa_data->label.data,
				    rsa_data->label.length, lHash.data,
				    lHash.length);
	RSA_TRACE("Hash the RSA Label returned 0x%08" PRIx32, ret);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;
	RSA_DUMPBUF("lHash", lHash.data, lHash.length);

	/*
	 * Step b
	 * Add PS 0's
	 * Note: DB is already filled with 0's at the allocation
	 */
	ps_size = rsa_data->key.n_size - rsa_data->message.length -
		  2 * rsa_data->digest_size - 2;
	RSA_TRACE("PS is %zu bytes", ps_size);

	/*
	 * Step c
	 * Set the value 0x01 after the lHash and the PS
	 * Concatenate result with input message
	 */
	DB.data[lHash.length + ps_size] = 0x01;
	memcpy(&DB.data[lHash.length + ps_size + 1], rsa_data->message.data,
	       rsa_data->message.length);

	RSA_DUMPBUF("DB", DB.data, DB.length);

	/*
	 * Step d
	 * Generate a random seed of hLen
	 */
	/* Allocate the seed buffer */
	retstatus = caam_calloc_align_buf(&seed, rsa_data->digest_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_encrypt;
	}

	/* Allocate the dbMask buffer */
	retstatus = caam_calloc_align_buf(&dbMask, db_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_encrypt;
	}

	ret = crypto_rng_read(seed.data, seed.length);
	RSA_TRACE("Get seed of %zu bytes (ret = 0x%08" PRIx32 ")", seed.length,
		  ret);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	RSA_DUMPBUF("Seed", seed.data, seed.length);

	/*
	 * Step e
	 * Generate a Mask of the seed value
	 * dbMask = MGF(seed, k - hLen - 1)
	 */
	mgf_data.hash_algo = rsa_data->hash_algo;
	mgf_data.digest_size = rsa_data->digest_size;
	mgf_data.seed.data = seed.data;
	mgf_data.seed.length = seed.length;
	mgf_data.mask.data = dbMask.data;
	mgf_data.mask.length = dbMask.length;

	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	/*
	 * Step f
	 * maskedDB = DB xor dbMask
	 */
	retstatus = caam_calloc_align_buf(&EM, rsa_data->key.n_size);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_oaep_encrypt;
	}

	maskedDB.data = &EM.data[1 + rsa_data->digest_size];
	maskedDB.length = dbMask.length;
	maskedDB.paddr = EM.paddr + sizeof(uint8_t) + rsa_data->digest_size;

	mod_op.n.length = maskedDB.length;
	mod_op.a.data = DB.data;
	mod_op.a.length = DB.length;
	mod_op.b.data = dbMask.data;
	mod_op.b.length = dbMask.length;
	mod_op.result.data = maskedDB.data;
	mod_op.result.length = maskedDB.length;

	ret = drvcrypt_xor_mod_n(&mod_op);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	/*
	 * Step g
	 * Generate a Mask of the maskedDB
	 * seedMask = MGF(maskedDB, hLen)
	 *
	 * Note: Use same buffer for seedMask and maskedSeed
	 */
	maskedSeed.data = &EM.data[1];
	maskedSeed.length = rsa_data->digest_size;
	maskedSeed.paddr = EM.paddr + sizeof(uint8_t);

	mgf_data.seed.data = maskedDB.data;
	mgf_data.seed.length = maskedDB.length;
	mgf_data.mask.data = maskedSeed.data;
	mgf_data.mask.length = maskedSeed.length;
	ret = rsa_data->mgf(&mgf_data);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	/*
	 * Step h
	 * maskedSeed = seed xor seedMask
	 */
	mod_op.n.length = maskedSeed.length;
	mod_op.a.data = seed.data;
	mod_op.a.length = seed.length;
	mod_op.b.data = maskedSeed.data;
	mod_op.b.length = maskedSeed.length;
	mod_op.result.data = maskedSeed.data;
	mod_op.result.length = maskedSeed.length;

	ret = drvcrypt_xor_mod_n(&mod_op);
	if (ret != TEE_SUCCESS)
		goto exit_oaep_encrypt;

	RSA_DUMPBUF("EM", EM.data, EM.length);

	/*
	 * Last Encryption of the EM of modulus size to Cipher
	 */
	memcpy(&enc_data, rsa_data, sizeof(enc_data));

	enc_data.message.data = EM.data;
	enc_data.message.length = EM.length;

	ret = do_caam_encrypt(&enc_data, RSA_ENCRYPT(NO));

exit_oaep_encrypt:
	caam_free_buf(&DB);
	caam_free_buf(&seed);
	caam_free_buf(&dbMask);
	caam_free_buf(&EM);

	return ret;
}

/*
 * CAAM RSA Encryption of the input message to a cipher
 *
 * @rsa_data   [in/out] RSA Data to encrypt
 * @operation  CAAM RSA Encryption operation
 */
static TEE_Result do_caam_encrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_rsa_keypair key = { };
	struct caamdmaobj msg = { };
	struct caamdmaobj cipher = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	uint32_t pdb_sgt_flags = 0;

	RSA_TRACE("RSA Encrypt mode %d", rsa_data->rsa_id);

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_ENC);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_encrypt;
	}

	/*
	 * Convert TEE rsa key type to CAAM rsa key type
	 * Push key value to memory
	 */
	retstatus = do_keypub_conv(&key, rsa_data->key.key);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto exit_encrypt;
	}

	/*
	 * ReAllocate the cipher result buffer with a maximum size
	 * of the Key Modulus's size (N) if not cache aligned
	 */
	ret = caam_dmaobj_output_sgtbuf(&cipher, rsa_data->cipher.data,
					rsa_data->cipher.length, key.n.length);
	if (ret)
		goto exit_encrypt;

	if (cipher.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_ENC_SGT_G;

	caam_dmaobj_cache_push(&cipher);

	/* Prepare the input message CAAM descriptor entry */
	ret = caam_dmaobj_input_sgtbuf(&msg, rsa_data->message.data,
				       rsa_data->message.length);
	if (ret)
		goto exit_encrypt;

	if (msg.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_ENC_SGT_F;

	caam_dmaobj_cache_push(&msg);

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_RSA_ENC_E_SIZE(key.e.length) |
					 PDB_RSA_ENC_N_SIZE(key.n.length) |
					 pdb_sgt_flags);
	caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
	caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
	caam_desc_add_ptr(desc, key.n.paddr);
	caam_desc_add_ptr(desc, key.e.paddr);
	caam_desc_add_word(desc, PDB_RSA_ENC_F_SIZE(rsa_data->message.length));
	caam_desc_add_word(desc, operation);

	/* Set the descriptor Header with length */
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));
	RSA_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		rsa_data->cipher.length = caam_dmaobj_copy_to_orig(&cipher);

		RSA_DUMPBUF("Output", rsa_data->cipher.data,
			    rsa_data->cipher.length);
		ret = caam_status_to_tee_result(retstatus);
	} else {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_encrypt:
	caam_free_desc(&desc);
	do_keypair_free(&key);
	caam_dmaobj_free(&msg);
	caam_dmaobj_free(&cipher);

	return ret;
}

/*
 * Get RSA key pair key type
 *
 * @kp RSA key pair
 */
static enum caam_key_type get_caam_key_type(const struct caam_rsa_keypair kp)
{
	switch (kp.format) {
	case RSA_PRIVATE_KEY_FORMAT_1:
		return kp.d.key_type;
	case RSA_PRIVATE_KEY_FORMAT_2:
		if (kp.p.key_type == kp.q.key_type &&
		    kp.q.key_type == kp.d.key_type)
			return kp.p.key_type;
		else
			return CAAM_KEY_MAX_VALUE;
	case RSA_PRIVATE_KEY_FORMAT_3:
		if (kp.p.key_type == kp.q.key_type &&
		    kp.q.key_type == kp.dp.key_type &&
		    kp.dp.key_type == kp.dq.key_type &&
		    kp.dq.key_type == kp.qp.key_type)
			return kp.p.key_type;
		else
			return CAAM_KEY_MAX_VALUE;
	default:
		return CAAM_KEY_MAX_VALUE;
	}
}

/*
 * CAAM RSA Decryption of the input cipher to a message
 *
 * @rsa_data   [in/out] RSA Data to decrypt
 * @operation  CAAM RSA Decryption operation
 */
static TEE_Result do_caam_decrypt(struct drvcrypt_rsa_ed *rsa_data,
				  uint32_t operation)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_rsa_keypair key = { };
	struct caamdmaobj cipher = { };
	struct caamdmaobj msg = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	uint32_t pdb_sgt_flags = 0;
	struct caambuf size_msg = { };
	struct caamkey tmp_1 = { };
	struct caamkey tmp_2 = { };
	enum caam_key_type g_key_type = CAAM_KEY_MAX_VALUE;

	RSA_TRACE("RSA Decrypt mode %d", rsa_data->rsa_id);

	/*
	 * Convert TEE rsa key type to CAAM rsa key type
	 * Push key value to memory
	 */
	retstatus = do_keypair_conv(&key, rsa_data->key.key);
	if (retstatus != CAAM_NO_ERROR) {
		RSA_TRACE("do_keypair_conv returned 0x%" PRIx32, retstatus);
		ret = caam_status_to_tee_result(retstatus);
		goto exit_decrypt;
	}

	/*
	 * Allocate the temporary result buffer with a maximum size
	 * of the Key Modulus's size (N)
	 */
	ret = caam_dmaobj_output_sgtbuf(&msg, rsa_data->message.data,
					rsa_data->message.length, key.n.length);

	if (ret)
		goto exit_decrypt;

	if (msg.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_DEC_SGT_F;

	caam_dmaobj_cache_push(&msg);

	/* Allocate the returned computed size when PKCS V1.5 */
	if (operation == RSA_DECRYPT(PKCS_V1_5)) {
		retstatus = caam_alloc_align_buf(&size_msg, 4);
		if (retstatus != CAAM_NO_ERROR)
			goto exit_decrypt;

		cache_operation(TEE_CACHEFLUSH, size_msg.data, size_msg.length);
	}

	/* Prepare the input cipher CAAM descriptor entry */
	ret = caam_dmaobj_input_sgtbuf(&cipher, rsa_data->cipher.data,
				       rsa_data->cipher.length);

	if (cipher.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_RSA_DEC_SGT_G;

	caam_dmaobj_cache_push(&cipher);

	/* Allocate the job descriptor function of the Private key format */
	switch (key.format) {
	case RSA_PRIVATE_KEY_FORMAT_1:
		desc = caam_calloc_desc(MAX_DESC_DEC_1);
		if (!desc) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_decrypt;
		}
		break;

	case RSA_PRIVATE_KEY_FORMAT_2:
	case RSA_PRIVATE_KEY_FORMAT_3:
		if (key.format == RSA_PRIVATE_KEY_FORMAT_2)
			desc = caam_calloc_desc(MAX_DESC_DEC_2);
		else
			desc = caam_calloc_desc(MAX_DESC_DEC_3);

		if (!desc) {
			ret = TEE_ERROR_OUT_OF_MEMORY;
			goto exit_decrypt;
		}
		/* Allocate two temporary buffers used by the CAAM */
		tmp_1.key_type = CAAM_KEY_PLAIN_TEXT;
		tmp_1.sec_size = key.p.sec_size;
		tmp_1.is_blob = false;

		retstatus = caam_key_alloc(&tmp_1);
		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto exit_decrypt;
		}

		tmp_2.key_type = CAAM_KEY_PLAIN_TEXT;
		tmp_2.sec_size = key.q.sec_size;
		tmp_2.is_blob = false;

		retstatus = caam_key_alloc(&tmp_2);
		if (retstatus != CAAM_NO_ERROR) {
			ret = caam_status_to_tee_result(retstatus);
			goto exit_decrypt;
		}

		caam_key_cache_op(TEE_CACHEFLUSH, &tmp_1);
		caam_key_cache_op(TEE_CACHEFLUSH, &tmp_2);
		break;

	default:
		ret = TEE_ERROR_GENERIC;
		goto exit_decrypt;
	}

	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/* Build the descriptor function of the Private Key format */
	switch (key.format) {
	case RSA_PRIVATE_KEY_FORMAT_1:
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_D_SIZE(key.d.sec_size) |
					   PDB_RSA_DEC_N_SIZE(key.n.length) |
					   pdb_sgt_flags);
		caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
		caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
		caam_desc_add_ptr(desc, key.n.paddr);
		caam_desc_add_ptr(desc, key.d.buf.paddr);

		break;

	case RSA_PRIVATE_KEY_FORMAT_2:
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_D_SIZE(key.d.sec_size) |
					   PDB_RSA_DEC_N_SIZE(key.n.length) |
					   pdb_sgt_flags);
		caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
		caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
		caam_desc_add_ptr(desc, key.d.buf.paddr);
		caam_desc_add_ptr(desc, key.p.buf.paddr);
		caam_desc_add_ptr(desc, key.q.buf.paddr);
		caam_desc_add_ptr(desc, tmp_1.buf.paddr);
		caam_desc_add_ptr(desc, tmp_2.buf.paddr);
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_Q_SIZE(key.q.sec_size) |
					   PDB_RSA_DEC_P_SIZE(key.p.sec_size));
		break;

	case RSA_PRIVATE_KEY_FORMAT_3:
		caam_desc_add_word(desc, PDB_RSA_DEC_N_SIZE(key.n.length) |
						 pdb_sgt_flags);
		caam_desc_add_ptr(desc, cipher.sgtbuf.paddr);
		caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
		caam_desc_add_ptr(desc, key.qp.buf.paddr);
		caam_desc_add_ptr(desc, key.p.buf.paddr);
		caam_desc_add_ptr(desc, key.q.buf.paddr);
		caam_desc_add_ptr(desc, key.dp.buf.paddr);
		caam_desc_add_ptr(desc, key.dq.buf.paddr);
		caam_desc_add_ptr(desc, tmp_1.buf.paddr);
		caam_desc_add_ptr(desc, tmp_2.buf.paddr);
		caam_desc_add_word(desc,
				   PDB_RSA_DEC_Q_SIZE(key.q.sec_size) |
					   PDB_RSA_DEC_P_SIZE(key.p.sec_size));
		break;

	default:
		ret = TEE_ERROR_GENERIC;
		goto exit_decrypt;
	}

	/* Set the Decryption operation type */
	operation |= PROT_RSA_DEC_KEYFORM(key.format);

	/* Get key type */
	g_key_type = get_caam_key_type(key);
	switch (g_key_type) {
	case CAAM_KEY_PLAIN_TEXT:
		operation |= PROT_RSA_KEY_ENC(NONE);
		break;
	case CAAM_KEY_BLACK_ECB:
		operation |= PROT_RSA_KEY_ENC(ECB);
		break;
	case CAAM_KEY_BLACK_CCM:
		operation |= PROT_RSA_KEY_ENC(CCM);
		break;
	default:
		ret = TEE_ERROR_GENERIC;
		goto exit_decrypt;
	}

	caam_desc_add_word(desc, operation);

	if (operation == RSA_DECRYPT(PKCS_V1_5)) {
		/* Get the PPKCS1 v1.5 Message length generated */
		caam_desc_add_word(desc,
				   ST_NOIMM_OFF(CLASS_DECO, REG_MATH0, 4, 4));
		caam_desc_add_ptr(desc, size_msg.paddr);
		/* Set the descriptor Header with length */
		desclen = caam_desc_get_len(desc);
#ifdef CFG_CAAM_64BIT
		caam_desc_update_hdr(desc,
				     DESC_HEADER_IDX(desclen, desclen - 1 - 3));
#else
		caam_desc_update_hdr(desc,
				     DESC_HEADER_IDX(desclen, desclen - 1 - 2));
#endif /* CFG_CAAM_64BIT */
	} else {
		desclen = caam_desc_get_len(desc);
		/* Set the descriptor Header with length */
		caam_desc_update_hdr(desc,
				     DESC_HEADER_IDX(desclen, desclen - 1));
	}

	RSA_DUMPDESC(desc);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus != CAAM_NO_ERROR) {
		RSA_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
		goto exit_decrypt;
	}

	if (operation == RSA_DECRYPT(NO) &&
	    rsa_data->rsa_id == DRVCRYPT_RSA_NOPAD) {
		rsa_data->message.length = caam_dmaobj_copy_ltrim_to_orig(&msg);
	} else {
		if (operation == RSA_DECRYPT(PKCS_V1_5)) {
			/* PKCS 1 v1.5 */
			cache_operation(TEE_CACHEINVALIDATE, size_msg.data,
					size_msg.length);

			/* Check if the original buffer size is large enough */
			if (msg.orig.length < caam_read_val32(size_msg.data)) {
				rsa_data->message.length =
						caam_read_val32(size_msg.data);
				ret = TEE_ERROR_SHORT_BUFFER;
				goto exit_decrypt;
			}

			msg.orig.length = caam_read_val32(size_msg.data);
			RSA_TRACE("New length %zu", msg.orig.length);
		}

		rsa_data->message.length = caam_dmaobj_copy_to_orig(&msg);
	}

	RSA_DUMPBUF("Output", rsa_data->message.data, rsa_data->message.length);
	ret = TEE_SUCCESS;

exit_decrypt:
	caam_free_desc(&desc);
	do_keypair_free(&key);
	caam_free_buf(&size_msg);
	caam_dmaobj_free(&msg);
	caam_dmaobj_free(&cipher);

	caam_key_free(&tmp_1);
	caam_key_free(&tmp_2);

	return ret;
}

/*
 * RSA Encryption
 *
 * @rsa_data   [in/out] RSA Data to encrypt / Cipher resulting
 */
static TEE_Result do_encrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
		ret = do_caam_encrypt(rsa_data, RSA_ENCRYPT(NO));
		break;

	case DRVCRYPT_RSA_PKCS_V1_5:
		ret = do_caam_encrypt(rsa_data, RSA_ENCRYPT(PKCS_V1_5));
		break;

	case DRVCRYPT_RSA_OAEP:
		ret = do_oaep_encoding(rsa_data);
		break;

	default:
		break;
	}

	return ret;
}

/*
 * RSA Decryption
 *
 * @rsa_data   [in/out] RSA Data to decrypt / Message resulting
 */
static TEE_Result do_decrypt(struct drvcrypt_rsa_ed *rsa_data)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;

	switch (rsa_data->rsa_id) {
	case DRVCRYPT_RSA_NOPAD:
	case DRVCRYPT_RSASSA_PKCS_V1_5:
	case DRVCRYPT_RSASSA_PSS:
		ret = do_caam_decrypt(rsa_data, RSA_DECRYPT(NO));
		break;

	case DRVCRYPT_RSA_PKCS_V1_5:
		ret = do_caam_decrypt(rsa_data, RSA_DECRYPT(PKCS_V1_5));
		break;

	case DRVCRYPT_RSA_OAEP:
		ret = do_oaep_decoding(rsa_data);
		break;

	default:
		break;
	}

	return ret;
}

/*
 * Registration of the RSA Driver
 */
static const struct drvcrypt_rsa driver_rsa = {
	.alloc_keypair = do_allocate_keypair,
	.alloc_publickey = do_allocate_publickey,
	.free_publickey = do_free_publickey,
	.free_keypair = do_free_keypair,
	.gen_keypair = do_gen_keypair,
	.encrypt = do_encrypt,
	.decrypt = do_decrypt,
	.optional.ssa_sign = NULL,
	.optional.ssa_verify = NULL,
};

enum caam_status caam_rsa_init(struct caam_jrcfg *caam_jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;
	vaddr_t jr_base = caam_jrcfg->base + caam_jrcfg->offset;

	if (caam_hal_ctrl_pknum(jr_base)) {
		caam_era = caam_hal_ctrl_era(jr_base);
		RSA_TRACE("CAAM Era %d", caam_era);

		if (!drvcrypt_register_rsa(&driver_rsa))
			retstatus = CAAM_NO_ERROR;
	}

	return retstatus;
}
