// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Implementation of DH
 */
#include <caam_acipher.h>
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_jr.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <string.h>

#ifdef CFG_CAAM_64BIT
#define MAX_DESC_KEY_GEN 14
#define MAX_DESC_SHARED  14
#else
#define MAX_DESC_KEY_GEN 9
#define MAX_DESC_SHARED  9
#endif

/*
 * Definition of the local DH Keypair
 */
struct caam_dh_keypair {
	struct caambuf g; /* Generator */
	struct caambuf p; /* Prime Number Modulus */
	struct caambuf x; /* Private key */
	struct caambuf y; /* Public key */
};

/*
 * Free local DH keypair
 *
 * @key DH keypair
 */
static void do_keypair_free(struct caam_dh_keypair *key)
{
	caam_free_buf(&key->g);
	caam_free_buf(&key->p);
	caam_free_buf(&key->x);
	caam_free_buf(&key->y);
}

/*
 * Convert Crypto DH Key p and g bignumbers to local buffers
 * (via keypair object).
 *
 * @outkey [out] Output keypair in local format
 * @inkey  Input key in TEE Crypto format
 */
static enum caam_status do_keypair_conv_p_g(struct caam_dh_keypair *outkey,
					    const struct dh_keypair *inkey)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	size_t p_size = 0;
	size_t field_size = 0;

	p_size = crypto_bignum_num_bytes(inkey->p);

	DH_TRACE("DH Convert Key Parameters (p,g) size %zu bytes", p_size);

	/* Prime Number Modulus */
	retstatus = caam_calloc_buf(&outkey->p, p_size);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	crypto_bignum_bn2bin(inkey->p, outkey->p.data);
	cache_operation(TEE_CACHECLEAN, outkey->p.data, outkey->p.length);

	/* Generator */
	retstatus = caam_calloc_buf(&outkey->g, p_size);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	/* Get the number of bytes of g to pad with 0's */
	field_size = crypto_bignum_num_bytes(inkey->g);
	crypto_bignum_bn2bin(inkey->g, outkey->g.data + p_size - field_size);
	cache_operation(TEE_CACHECLEAN, outkey->g.data, outkey->g.length);

	return CAAM_NO_ERROR;
}

/*
 * Convert Crypto DH Private Key to a local Private Key (via keypair object)
 *
 * @outkey [out] Output local keypair
 * @inkey  Input Private key in TEE Crypto format
 */
static enum caam_status do_keypriv_conv(struct caam_dh_keypair *outkey,
					const struct dh_keypair *inkey)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	size_t key_size = inkey->xbits / 8;
	size_t p_size = 0;

	if (!key_size)
		key_size = crypto_bignum_num_bytes(inkey->x);

	DH_TRACE("DH Convert Private Key size %zu bytes", key_size);

	/* Prime */
	p_size = crypto_bignum_num_bytes(inkey->p);
	retstatus = caam_calloc_buf(&outkey->p, p_size);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	crypto_bignum_bn2bin(inkey->p, outkey->p.data);
	cache_operation(TEE_CACHECLEAN, outkey->p.data, outkey->p.length);

	/* Private Key X */
	retstatus = caam_calloc_buf(&outkey->x, key_size);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	crypto_bignum_bn2bin(inkey->x, outkey->x.data);
	cache_operation(TEE_CACHECLEAN, outkey->x.data, outkey->x.length);

	return CAAM_NO_ERROR;
}

/*
 * Convert Crypto DH Public Key to local Public Key (via a keypair object)
 *
 * @outkey [out] Output local keypair
 * @inkey  Input Public key in TEE Crypto format
 */
static enum caam_status do_keypub_conv(struct caam_dh_keypair *outkey,
				       const struct bignum *inkey)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	size_t key_size = 0;

	key_size = crypto_bignum_num_bytes((struct bignum *)inkey);
	DH_TRACE("DH Convert Keypair size %zu bytes", key_size);

	/* Public Key Y */
	retstatus = caam_calloc_buf(&outkey->y, key_size);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	crypto_bignum_bn2bin(inkey, outkey->y.data);
	cache_operation(TEE_CACHECLEAN, outkey->y.data, outkey->y.length);

	return CAAM_NO_ERROR;
}

/*
 * Allocate a TEE DH keypair.
 * Note: The subprime q is not used but it must be allocated to prevent
 * system referencing issues when object is destroyed.
 *
 * @key       Keypair
 * @size_bits Key size in bits
 */
static TEE_Result do_allocate_keypair(struct dh_keypair *key, size_t size_bits)
{
	DH_TRACE("Allocate Keypair of %zu bits", size_bits);

	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Generator Scalar */
	key->g = crypto_bignum_allocate(size_bits);
	if (!key->g)
		goto err;

	/* Allocate Prime Number Modulus */
	key->p = crypto_bignum_allocate(size_bits);
	if (!key->p)
		goto err;

	/* Allocate Private key X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err;

	/* Allocate Public Key Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err;

	/* Allocate Subprime even if not used */
	key->q = crypto_bignum_allocate(size_bits);
	if (!key->q)
		goto err;

	return TEE_SUCCESS;

err:
	DH_TRACE("Allocation error");

	crypto_bignum_free(key->g);
	crypto_bignum_free(key->p);
	crypto_bignum_free(key->x);
	crypto_bignum_free(key->y);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Generates an DH keypair
 * Keypair @key contains the input prime p and generator g values
 * The function calculates private x and public y, knowing that the
 * number of bits of x is either key_size if specified or p size.
 *
 * @key      [in/out] Keypair
 * @q        Sub Prime (not used)
 * @key_size Key size in bits multiple of 8 bits
 */
static TEE_Result do_gen_keypair(struct dh_keypair *key,
				 struct bignum *q __unused, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct caam_dh_keypair caam_dh_key = { };
	struct caambuf dh_r = { };
	size_t n_bytes = key_size / 8;
	size_t l_bytes = 0;
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	int counter = 0;

	l_bytes = crypto_bignum_num_bytes(key->p);
	if (!l_bytes)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * If @key_size not specified, private key size is
	 * same as the public key size (same as prime size)
	 */
	if (!n_bytes)
		n_bytes = l_bytes;

	/*
	 * CAAM private key support is limited to the descriptor PDB
	 * N maximum value (PDB_DL_KEY_N_MASK)
	 */
	if (n_bytes > PDB_DL_KEY_N_MASK)
		n_bytes = PDB_DL_KEY_N_MASK;

	DH_TRACE("Request %zu bits key -> so do %zu bytes key", key_size,
		 n_bytes);

	/* Allocate the job used to prepare the operation */
	desc = caam_calloc_desc(MAX_DESC_KEY_GEN);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Allocate Private Key to be generated */
	retstatus = caam_calloc_align_buf(&caam_dh_key.x, n_bytes);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}
	cache_operation(TEE_CACHEFLUSH, caam_dh_key.x.data,
			caam_dh_key.x.length);

	/* Allocate Public Key to be generated */
	retstatus = caam_calloc_align_buf(&caam_dh_key.y, l_bytes);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}
	cache_operation(TEE_CACHEFLUSH, caam_dh_key.y.data,
			caam_dh_key.y.length);

	/* Allocate Private Key modulus (r) and fill it with one's */
	retstatus = caam_calloc_buf(&dh_r, n_bytes);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	memset(dh_r.data, UINT8_MAX, dh_r.length);
	cache_operation(TEE_CACHECLEAN, dh_r.data, dh_r.length);

	/* Generator and Prime */
	retstatus = do_keypair_conv_p_g(&caam_dh_key, key);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/*
	 * Build the descriptor using the PDB Public Key generation
	 * block (PD=0)
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_DL_KEY_L_SIZE(l_bytes) |
				 PDB_DL_KEY_N_SIZE(n_bytes));
	caam_desc_add_ptr(desc, caam_dh_key.p.paddr);
	caam_desc_add_ptr(desc, dh_r.paddr);
	caam_desc_add_ptr(desc, caam_dh_key.g.paddr);
	caam_desc_add_ptr(desc, caam_dh_key.x.paddr);
	caam_desc_add_ptr(desc, caam_dh_key.y.paddr);
	caam_desc_add_word(desc, PK_KEYPAIR_GEN(DL));

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	DH_DUMPDESC(desc);

	/*
	 * If the Secure Key X doesn't have the correct size
	 * retry a new generation.
	 * Retry 10 times before returing an error to not lock the system.
	 */
	for (counter = 0; counter < 10; counter++) {
		memset(&jobctx, 0, sizeof(jobctx));
		jobctx.desc = desc;
		retstatus = caam_jr_enqueue(&jobctx, NULL);

		if (retstatus == CAAM_NO_ERROR) {
			cache_operation(TEE_CACHEINVALIDATE, caam_dh_key.x.data,
					caam_dh_key.x.length);
			cache_operation(TEE_CACHEINVALIDATE, caam_dh_key.y.data,
					caam_dh_key.y.length);

			/* Copy Private and Public keypair */
			ret = crypto_bignum_bin2bn(caam_dh_key.x.data,
						   caam_dh_key.x.length,
						   key->x);
			if (ret != TEE_SUCCESS)
				goto out;

			if (crypto_bignum_num_bytes(key->x) != n_bytes) {
				DH_TRACE("Error X size=%zu expected %zu",
					 crypto_bignum_num_bytes(key->x),
					 n_bytes);
				DH_DUMPBUF("X", caam_dh_key.x.data,
					   caam_dh_key.x.length);
				DH_DUMPBUF("Y", caam_dh_key.y.data,
					   caam_dh_key.y.length);
				continue;
			}

			ret = crypto_bignum_bin2bn(caam_dh_key.y.data,
						   caam_dh_key.y.length,
						   key->y);
			if (ret != TEE_SUCCESS)
				goto out;

			/* Set the Private Key size in bits */
			key->xbits = n_bytes * 8;

			ret = TEE_SUCCESS;
			goto out;
		} else {
			DH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
			ret = job_status_to_tee_result(jobctx.status);
			goto out;
		}
	}

out:
	caam_free_desc(&desc);
	caam_free_buf(&dh_r);
	do_keypair_free(&caam_dh_key);

	return ret;
}

/*
 * Compute the shared secret data from DH Private key and Public Key
 *
 * @sdata   [in/out] DH Shared Secret data
 */
static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct dh_keypair *inkeypair = sdata->key_priv;
	struct caam_dh_keypair caam_dh_key = { };
	struct caamdmaobj secret = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	uint32_t pdb_sgt_flags = 0;

	DH_TRACE("DH Shared Secret");

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_SHARED);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * ReAllocate the secret result buffer with a maximum size
	 * of the secret size if not cache aligned
	 */
	ret = caam_dmaobj_output_sgtbuf(&secret, sdata->secret.data,
					sdata->secret.length,
					sdata->secret.length);
	if (ret)
		goto out;

	if (secret.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKDH_SECRET;

	caam_dmaobj_cache_push(&secret);

	/* Convert the Private key to local key */
	retstatus = do_keypriv_conv(&caam_dh_key, inkeypair);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Convert the Public key to local key */
	retstatus = do_keypub_conv(&caam_dh_key, sdata->key_pub);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/*
	 * Build the descriptor using PDB Shared Secret
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, pdb_sgt_flags |
				 PDB_DL_KEY_L_SIZE(caam_dh_key.y.length) |
				 PDB_DL_KEY_N_SIZE(caam_dh_key.x.length));
	/* Prime */
	caam_desc_add_ptr(desc, caam_dh_key.p.paddr);
	/* Modulus - Not used */
	caam_desc_add_ptr(desc, 0);
	/* Public key */
	caam_desc_add_ptr(desc, caam_dh_key.y.paddr);
	/* Private key */
	caam_desc_add_ptr(desc, caam_dh_key.x.paddr);
	/* Output secret */
	caam_desc_add_ptr(desc, secret.sgtbuf.paddr);

	caam_desc_add_word(desc, SHARED_SECRET(DL));
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	DH_DUMPDESC(desc);
	jobctx.desc = desc;

	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		sdata->secret.length = caam_dmaobj_copy_to_orig(&secret);

		DH_DUMPBUF("Secret", sdata->secret.data, sdata->secret.length);
		ret = caam_status_to_tee_result(retstatus);
	} else {
		DH_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_free_desc(&desc);
	do_keypair_free(&caam_dh_key);
	caam_dmaobj_free(&secret);

	return ret;
}

/*
 * Registration of the ECC Driver
 */
static struct drvcrypt_dh driver_dh = {
	.alloc_keypair = do_allocate_keypair,
	.gen_keypair = do_gen_keypair,
	.shared_secret = do_shared_secret,
};

enum caam_status caam_dh_init(struct caam_jrcfg *caam_jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;
	vaddr_t jr_base = caam_jrcfg->base + caam_jrcfg->offset;

	if (caam_hal_ctrl_pknum(jr_base) &&
	    drvcrypt_register_dh(&driver_dh) == TEE_SUCCESS)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}
