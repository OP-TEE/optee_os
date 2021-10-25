// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2021 NXP
 *
 * Implementation of ECC functions
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
#include <string.h>
#include <tee/cache.h>

#ifdef CFG_CAAM_64BIT
#define MAX_DESC_KEY_GEN 8
#define MAX_DESC_SIGN    13
#define MAX_DESC_VERIFY  15
#define MAX_DESC_SHARED  10
#else
#define MAX_DESC_KEY_GEN 6
#define MAX_DESC_SIGN    9
#define MAX_DESC_VERIFY  10
#define MAX_DESC_SHARED  7
#endif

/*
 * Definition of the local ECC Keypair
 *   Public Key format (x, y)
 *   Private Key format (d)
 */
struct caam_ecc_keypair {
	struct caambuf xy;
	struct caambuf d;
};

/*
 * Free local ECC keypair
 *
 * @key ECC keypair
 */
static void do_keypair_free(struct caam_ecc_keypair *key)
{
	caam_free_buf(&key->xy);
	caam_free_buf(&key->d);
}

/*
 * Convert Crypto ECC Key to local ECC Public Key
 *
 * @outkey    [out] Output keypair in local format
 * @inkey     Input key in TEE Crypto format
 * @size_sec  Security size in bytes
 */
static enum caam_status do_keypub_conv(struct caam_ecc_keypair *outkey,
				       const struct ecc_public_key *inkey,
				       size_t size_sec)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	size_t x_size = 0;
	size_t y_size = 0;

	ECC_TRACE("ECC Convert Public Key size %zu bytes", size_sec);

	/* Point (x y) is twice security key size */
	retstatus = caam_calloc_buf(&outkey->xy, 2 * size_sec);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	/* Copy x and y and get the number of bytes to pad with 0's */
	x_size = crypto_bignum_num_bytes(inkey->x);
	crypto_bignum_bn2bin(inkey->x, outkey->xy.data + size_sec - x_size);

	y_size = crypto_bignum_num_bytes(inkey->y);
	crypto_bignum_bn2bin(inkey->y, outkey->xy.data + 2 * size_sec - y_size);

	cache_operation(TEE_CACHECLEAN, outkey->xy.data, outkey->xy.length);

	return CAAM_NO_ERROR;
}

/*
 * Convert Crypto ECC Key to local ECC Keypair Key
 * Don't convert the exponent e not used in decrytion
 *
 * @outkey    [out] Output keypair in local format
 * @inkey     Input key in TEE Crypto format
 * @size_sec  Security size in bytes
 */
static enum caam_status do_keypair_conv(struct caam_ecc_keypair *outkey,
					const struct ecc_keypair *inkey,
					size_t size_sec)
{
	enum caam_status retstatus = CAAM_OUT_MEMORY;
	size_t d_size = 0;

	ECC_TRACE("ECC Convert Keypair size %zu bytes", size_sec);

	/* Private key is only scalar d of sec_size bytes */
	retstatus = caam_calloc_buf(&outkey->d, size_sec);
	if (retstatus != CAAM_NO_ERROR)
		return retstatus;

	/* Get the number of bytes of d to pad with 0's */
	d_size = crypto_bignum_num_bytes(inkey->d);
	crypto_bignum_bn2bin(inkey->d, outkey->d.data + size_sec - d_size);

	cache_operation(TEE_CACHECLEAN, outkey->d.data, outkey->d.length);

	return CAAM_NO_ERROR;
}

/*
 * Convert TEE ECC Curve to CAAM ECC Curve
 *
 * @tee_curve  TEE ECC Curve
 */
static enum caam_ecc_curve get_caam_curve(uint32_t tee_curve)
{
	enum caam_ecc_curve caam_curve = CAAM_ECC_UNKNOWN;

	if (tee_curve > 0 &&
	    tee_curve < CAAM_ECC_MAX + TEE_ECC_CURVE_NIST_P192) {
		/*
		 * Realign TEE Curve assuming NIST_P192 is the first entry in
		 * the list of supported ECC curves.
		 */
		caam_curve = tee_curve - TEE_ECC_CURVE_NIST_P192
			     + CAAM_ECC_P192;
	}

	return caam_curve;
}

/*
 * Allocate a ECC keypair
 *
 * @key        Keypair
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_keypair(struct ecc_keypair *key, size_t size_bits)
{
	ECC_TRACE("Allocate Keypair of %zu bits", size_bits);

	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Secure Scalar */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err;

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err;

	return TEE_SUCCESS;

err:
	ECC_TRACE("Allocation error");

	crypto_bignum_free(key->d);
	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Allocate an ECC Public Key
 *
 * @key        Public Key
 * @size_bits  Key size in bits
 */
static TEE_Result do_allocate_publickey(struct ecc_public_key *key,
					size_t size_bits)
{
	ECC_TRACE("Allocate Public Key of %zu bits", size_bits);

	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err;

	return TEE_SUCCESS;

err:
	ECC_TRACE("Allocation error");

	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/*
 * Free an ECC public key
 *
 * @key  Public Key
 */
static void do_free_publickey(struct ecc_public_key *key)
{
	crypto_bignum_free(key->x);
	crypto_bignum_free(key->y);
}

/*
 * Generate ECC keypair
 *
 * @key        [out] Keypair
 * @key_size   Key size in bits multiple of 8 bits
 */
static TEE_Result do_gen_keypair(struct ecc_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct caambuf d = { };
	struct caambuf xy = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;

	ECC_TRACE("Generate Keypair of %zu bits", key_size);

	/* Verify first if the curve is supported */
	curve = get_caam_curve(key->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job used to prepare the operation */
	desc = caam_calloc_desc(MAX_DESC_KEY_GEN);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Allocate secure and public keys in one buffer
	 * Secure key size = key_size align in bytes
	 * Public key size = (key_size * 2) align in bytes
	 */
	retstatus = caam_alloc_align_buf(&d, (key_size / 8) * 3);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/* Build the xy buffer to simplify the code */
	xy.data = d.data + key_size / 8;
	xy.length = 2 * (key_size / 8);
	xy.paddr = d.paddr + key_size / 8;

	/* Build the descriptor using Predifined ECC curve */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_PKGEN_PD1 | PDB_ECC_ECDSEL(curve));
	caam_desc_add_ptr(desc, d.paddr);
	caam_desc_add_ptr(desc, xy.paddr);
	caam_desc_add_word(desc, PK_KEYPAIR_GEN(ECC));

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;
	cache_operation(TEE_CACHEFLUSH, d.data, d.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, d.data, d.length);

		/* Copy all keypair parameters */
		ret = crypto_bignum_bin2bn(d.data, key_size / 8, key->d);
		if (ret != TEE_SUCCESS)
			goto out;

		ret = crypto_bignum_bin2bn(xy.data, xy.length / 2, key->x);
		if (ret != TEE_SUCCESS)
			goto out;

		ret = crypto_bignum_bin2bn(xy.data + xy.length / 2,
					   xy.length / 2, key->y);
		if (ret != TEE_SUCCESS)
			goto out;

		ECC_DUMPBUF("D", d.data, key_size / 8);
		ECC_DUMPBUF("X", xy.data, xy.length / 2);
		ECC_DUMPBUF("Y", xy.data + xy.length / 2, xy.length / 2);
	} else {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_free_desc(&desc);
	caam_free_buf(&d);

	return ret;
}

/*
 * Signature of ECC message
 * Note the message to sign is already hashed
 *
 * @sdata   [in/out] ECC data to sign / Signature
 */
static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct ecc_keypair *inkey = sdata->key;
	struct caam_ecc_keypair ecckey = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	struct caamdmaobj msg = { };
	size_t sign_len = 0;
	struct caamdmaobj sign_c = { };
	struct caamdmaobj sign_d = { };
	uint32_t pdb_sgt_flags = 0;

	ECC_TRACE("ECC Signature");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inkey->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_SIGN);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Convert the private key to a local key */
	retstatus = do_keypair_conv(&ecckey, inkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/* Prepare the input message CAAM Descriptor entry */
	ret = caam_dmaobj_input_sgtbuf(&msg, sdata->message.data,
				       sdata->message.length);
	if (ret)
		goto out;

	if (msg.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKSIGN_MSG;

	caam_dmaobj_cache_push(&msg);

	ECC_DUMPBUF("Message", sdata->message.data, sdata->message.length);

	/*
	 * ReAllocate the signature result buffer with a maximum size
	 * of the roundup to 16 bytes of the secure size in bytes if
	 * the signature buffer is not aligned or too short.
	 *
	 *  - 1st Part: size_sec
	 *  - 2nd Part: size_sec roundup to 16 bytes
	 */
	sign_len = ROUNDUP(sdata->size_sec, 16) + sdata->size_sec;

	ret = caam_dmaobj_output_sgtbuf(&sign_c, sdata->signature.data,
					sdata->signature.length, sign_len);
	if (ret)
		goto out;

	if (sign_c.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKSIGN_SIGN_C;

	/* Derive sign_d from created sign_c DMA object */
	ret = caam_dmaobj_derive_sgtbuf(&sign_d, &sign_c, sdata->size_sec,
					ROUNDUP(sdata->size_sec, 16));
	if (ret)
		goto out;

	if (sign_d.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKSIGN_SIGN_D;

	caam_dmaobj_cache_push(&sign_c);

	/* Build the descriptor using Predifined ECC curve */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_PKSIGN_PD1 | PDB_ECC_ECDSEL(curve) |
				 pdb_sgt_flags);
	/* Secret key */
	caam_desc_add_ptr(desc, ecckey.d.paddr);
	/* Input message */
	caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
	/* Signature 1st part */
	caam_desc_add_ptr(desc, sign_c.sgtbuf.paddr);
	/* Signature 2nd part */
	caam_desc_add_ptr(desc, sign_d.sgtbuf.paddr);
	/* Message length */
	caam_desc_add_word(desc, sdata->message.length);

	caam_desc_add_word(desc, DSA_SIGN(ECC));

	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;

	retstatus = caam_jr_enqueue(&jobctx, NULL);
	if (retstatus == CAAM_NO_ERROR) {
		sign_c.orig.length = 2 * sdata->size_sec;
		sdata->signature.length = caam_dmaobj_copy_to_orig(&sign_c);

		ECC_DUMPBUF("Signature", sdata->signature.data,
			    sdata->signature.length);

		ret = caam_status_to_tee_result(retstatus);
	} else {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);
	caam_dmaobj_free(&msg);
	caam_dmaobj_free(&sign_d);
	caam_dmaobj_free(&sign_c);

	return ret;
}

/*
 * Verification of the Signature of ECC message
 * Note the message is already hashed
 *
 * @sdata   [in/out] ECC Signature to verify
 */
static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct ecc_public_key *inkey = sdata->key;
	struct caam_ecc_keypair ecckey = { };
	struct caambuf tmp = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	struct caamdmaobj msg = { };
	struct caamdmaobj sign_c = { };
	struct caamdmaobj sign_d = { };
	uint32_t pdb_sgt_flags = 0;

	ECC_TRACE("ECC Verify");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inkey->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_VERIFY);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Convert the Public key to local key */
	retstatus = do_keypub_conv(&ecckey, inkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/* Prepare the input message CAAM Descriptor entry */
	ret = caam_dmaobj_input_sgtbuf(&msg, sdata->message.data,
				       sdata->message.length);
	if (ret)
		goto out;

	if (msg.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKVERIF_MSG;

	caam_dmaobj_cache_push(&msg);

	/*
	 * Prepare the 1st Part of the signature
	 * Handle the full signature in case signature buffer needs to
	 * be reallocated.
	 */
	ret = caam_dmaobj_input_sgtbuf(&sign_c, sdata->signature.data,
				       sdata->signature.length);
	if (ret)
		goto out;

	if (sign_c.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKVERIF_SIGN_C;

	/* Prepare the 2nd Part of the signature, derived from sign_c */
	ret = caam_dmaobj_derive_sgtbuf(&sign_d, &sign_c, sdata->size_sec,
					sdata->size_sec);
	if (ret)
		goto out;

	if (sign_d.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKVERIF_SIGN_D;

	caam_dmaobj_cache_push(&sign_c);

	/* Allocate a Temporary buffer used by the CAAM */
	retstatus = caam_alloc_align_buf(&tmp, 2 * sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/* Build the descriptor using Predifined ECC curve */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_PKVERIFY_PD1 | PDB_ECC_ECDSEL(curve) |
				 pdb_sgt_flags);
	/* Public key */
	caam_desc_add_ptr(desc, ecckey.xy.paddr);
	/* Input message */
	caam_desc_add_ptr(desc, msg.sgtbuf.paddr);
	/* Signature 1st part */
	caam_desc_add_ptr(desc, sign_c.sgtbuf.paddr);
	/* Signature 2nd part */
	caam_desc_add_ptr(desc, sign_d.sgtbuf.paddr);
	/* Temporary buffer */
	caam_desc_add_ptr(desc, tmp.paddr);
	/* Message length */
	caam_desc_add_word(desc, sdata->message.length);

	caam_desc_add_word(desc, DSA_VERIFY(ECC));
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;

	cache_operation(TEE_CACHEFLUSH, tmp.data, tmp.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_JOB_STATUS && !jobctx.status) {
		ECC_TRACE("ECC Verify Status 0x%08" PRIx32, jobctx.status);
		ret = TEE_ERROR_SIGNATURE_INVALID;
	} else if (retstatus != CAAM_NO_ERROR) {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	} else {
		ret = caam_status_to_tee_result(retstatus);
	}

out:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);
	caam_free_buf(&tmp);
	caam_dmaobj_free(&msg);
	caam_dmaobj_free(&sign_c);
	caam_dmaobj_free(&sign_d);

	return ret;
}

/*
 * Compute the shared secret data from ECC Private key and Public Key
 *
 * @sdata   [in/out] ECC Shared Secret data
 */
static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	enum caam_ecc_curve curve = CAAM_ECC_UNKNOWN;
	struct ecc_keypair *inprivkey = sdata->key_priv;
	struct ecc_public_key *inpubkey = sdata->key_pub;
	struct caam_ecc_keypair ecckey = { };
	struct caam_jobctx jobctx = { };
	uint32_t *desc = NULL;
	uint32_t desclen = 0;
	struct caamdmaobj secret = { };
	uint32_t pdb_sgt_flags = 0;

	ECC_TRACE("ECC Shared Secret");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inpubkey->curve);
	if (curve == CAAM_ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job descriptor */
	desc = caam_calloc_desc(MAX_DESC_SHARED);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Convert the Private key to local key */
	retstatus = do_keypair_conv(&ecckey, inprivkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/* Convert the Public key to local key */
	retstatus = do_keypub_conv(&ecckey, inpubkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = caam_status_to_tee_result(retstatus);
		goto out;
	}

	/*
	 * Re-allocate the secret result buffer with a maximum size
	 * of the secret size if not cache aligned
	 */
	ret = caam_dmaobj_output_sgtbuf(&secret, sdata->secret.data,
					sdata->secret.length, sdata->size_sec);
	if (ret)
		goto out;

	if (secret.sgtbuf.sgt_type)
		pdb_sgt_flags |= PDB_SGT_PKDH_SECRET;

	caam_dmaobj_cache_push(&secret);

	/* Build the descriptor using Predifined ECC curve */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));
	caam_desc_add_word(desc, PDB_SHARED_SECRET_PD1 | PDB_ECC_ECDSEL(curve) |
				 pdb_sgt_flags);
	/* Public key */
	caam_desc_add_ptr(desc, ecckey.xy.paddr);
	/* Private key */
	caam_desc_add_ptr(desc, ecckey.d.paddr);
	/* Output secret */
	caam_desc_add_ptr(desc, secret.sgtbuf.paddr);

	caam_desc_add_word(desc, SHARED_SECRET(ECC));
	desclen = caam_desc_get_len(desc);
	caam_desc_update_hdr(desc, DESC_HEADER_IDX(desclen, desclen - 1));

	ECC_DUMPDESC(desc);

	jobctx.desc = desc;

	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		sdata->secret.length = caam_dmaobj_copy_to_orig(&secret);

		ECC_DUMPBUF("Secret", sdata->secret.data, sdata->secret.length);

		ret = caam_status_to_tee_result(retstatus);
	} else {
		ECC_TRACE("CAAM Status 0x%08" PRIx32, jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

out:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);
	caam_dmaobj_free(&secret);

	return ret;
}

/*
 * Registration of the ECC Driver
 */
static struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair = do_allocate_keypair,
	.alloc_publickey = do_allocate_publickey,
	.free_publickey = do_free_publickey,
	.gen_keypair = do_gen_keypair,
	.sign = do_sign,
	.verify = do_verify,
	.shared_secret = do_shared_secret,
};

enum caam_status caam_ecc_init(struct caam_jrcfg *caam_jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;
	vaddr_t jr_base = caam_jrcfg->base + caam_jrcfg->offset;

	if (caam_hal_ctrl_pknum(jr_base))
		if (drvcrypt_register_ecc(&driver_ecc) == TEE_SUCCESS)
			retstatus = CAAM_NO_ERROR;

	return retstatus;
}
