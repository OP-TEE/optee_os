// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_ecc.c
 *
 * @brief   CAAM ECC manager.\n
 *          Implementation of ECC functions
 */

/* Standard includes */
#include <string.h>

/* Global includes */
#include <mm/core_memprot.h>
#include <tee/cache.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>

/* Local includes */
#include "caam_acipher.h"
#include "caam_common.h"
#include "caam_jr.h"

/* Utils includes */
#include "utils_mem.h"
#include "utils_status.h"

/**
 * @brief   Definition of the local ECC Keypair
 *          Public Key format (x, y)
 *          Private Key format (d)
 */
struct caam_ecc_keypair {
	struct caambuf xy;  ///< Public key - (x, y) ecc point
	struct caambuf d;   ///< Private key - d scalar
};

/**
 * @brief  Free local RSA keypair
 *
 * @param[in]  key  RSA keypair
 */
static void do_keypair_free(struct caam_ecc_keypair *key)
{
	caam_free_buf(&key->xy);
	caam_free_buf(&key->d);
}

/**
 * @brief   Convert Crypto ECC Key to local ECC Public Key
 *          Ensure Key is push in physical memory
 *
 * @param[out] outkey   Output keypair in local format
 * @param[in]  inkey    Input key in TEE Crypto format
 * @param[in]  size_sec Security size in bytes
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_OUT_MEMORY  Allocation error
 */
static enum CAAM_Status do_keypub_conv(struct caam_ecc_keypair *outkey,
	const struct ecc_public_key *inkey, size_t size_sec)
{
	enum CAAM_Status retstatus;
	size_t x_size, y_size;

	ECC_TRACE("ECC Convert Public Key size %d bytes", size_sec);

	/* Point (x y) is twice security key size */
	retstatus = caam_alloc_buf(&outkey->xy, (2 * size_sec));
	if (retstatus != CAAM_NO_ERROR)
		return CAAM_OUT_MEMORY;

	/*
	 * Copy x value
	 */
	/* Get the number of bytes of x to pad with 0's */
	x_size = crypto_bignum_num_bytes(inkey->x);
	crypto_bignum_bn2bin(inkey->x, (outkey->xy.data + size_sec - x_size));

	/*
	 * Copy y value
	 */
	/* Get the number of bytes of y to pad with 0's */
	y_size = crypto_bignum_num_bytes(inkey->y);
	crypto_bignum_bn2bin(inkey->y, (outkey->xy.data +
				(2 * size_sec) - y_size));

	cache_operation(TEE_CACHECLEAN, outkey->xy.data,
		outkey->xy.length);

	return CAAM_NO_ERROR;
}

/**
 * @brief   Convert Crypto ECC Key to local ECC Keypair Key
 *          Ensure Key is push in physical memory
 *          Don't convert the exponent e not used in decrytion
 *
 * @param[out] outkey   Output keypair in local format
 * @param[in]  inkey    Input key in TEE Crypto format
 * @param[in]  size_sec Security size in bytes
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_OUT_MEMORY  Allocation error
 */
static enum CAAM_Status do_keypair_conv(struct caam_ecc_keypair *outkey,
		const struct ecc_keypair *inkey, size_t size_sec)
{
	enum CAAM_Status retstatus;
	size_t d_size;

	ECC_TRACE("ECC Convert Keypair size %d bytes", size_sec);

	/* Private key is only scalar d of sec_size bytes */
	retstatus = caam_alloc_buf(&outkey->d, size_sec);
	if (retstatus != CAAM_NO_ERROR)
		return CAAM_OUT_MEMORY;

	/* Get the number of bytes of d to pad with 0's */
	d_size = crypto_bignum_num_bytes(inkey->d);
	crypto_bignum_bn2bin(inkey->d, (outkey->d.data + size_sec - d_size));

	cache_operation(TEE_CACHECLEAN, outkey->d.data, outkey->d.length);

	return CAAM_NO_ERROR;
}

/**
 * @brief   Convert TEE ECC Curve to CAAM ECC Curve
 *
 * @param[in] tee_curve  TEE ECC Curve
 *
 * @retval CAAM ECC Curve ID
 * @retval ECC_UNKNOWN if not found
 */
static enum caam_ecc_curve get_caam_curve(uint32_t tee_curve)
{
	enum caam_ecc_curve caam_curve = ECC_UNKNOWN;

	if ((tee_curve > 0) &&
			(tee_curve < (ECC_MAX + TEE_ECC_CURVE_NIST_P192))) {
		/*
		 * Realign TEE Curve knowing that first in the list is the
		 * NIST_P192
		 */
		caam_curve = (tee_curve - TEE_ECC_CURVE_NIST_P192) + ECC_P192;
	}

	return caam_curve;
}

/**
 * @brief   Allocate a ECC keypair
 *
 * @param[in]  key        Keypair
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_keypair(struct ecc_keypair *key,
					size_t size_bits)
{
	ECC_TRACE("Allocate Keypair of %d bits", size_bits);

	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Secure Scalar */
	key->d = crypto_bignum_allocate(size_bits);
	if (!key->d)
		goto err_alloc_keypair;

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err_alloc_keypair;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err_alloc_keypair;

	return TEE_SUCCESS;

err_alloc_keypair:
	ECC_TRACE("Allocation error");

	crypto_bignum_free(key->d);
	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Allocate an ECC Public Key
 *
 * @param[in]  key        Public Key
 * @param[in]  size_bits  Key size in bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 */
static TEE_Result do_allocate_publickey(struct ecc_public_key *key,
					size_t size_bits)
{
	ECC_TRACE("Allocate Public Key of %d bits", size_bits);

	/* Initialize the key fields to NULL */
	memset(key, 0, sizeof(*key));

	/* Allocate Public coordinate X */
	key->x = crypto_bignum_allocate(size_bits);
	if (!key->x)
		goto err_alloc_publickey;

	/* Allocate Public coordinate Y */
	key->y = crypto_bignum_allocate(size_bits);
	if (!key->y)
		goto err_alloc_publickey;

	return TEE_SUCCESS;

err_alloc_publickey:
	ECC_TRACE("Allocation error");

	crypto_bignum_free(key->x);

	return TEE_ERROR_OUT_OF_MEMORY;
}

/**
 * @brief   Free an ECC public key
 *
 * @param[in]  key        Public Key
 */
static void do_free_publickey(struct ecc_public_key *key)
{
	crypto_bignum_free(key->x);
	crypto_bignum_free(key->y);
}

/**
 * @brief   Generates an ECC keypair
 *
 * @param[out] key        Keypair
 * @param[in]  key_size   Key size in bits multiple of 8 bits
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_gen_keypair(struct ecc_keypair *key, size_t key_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	enum CAAM_Status retstatus;

	enum caam_ecc_curve curve;

	struct caambuf d  = {0};
	struct caambuf xy = {0};

	struct jr_jobctx jobctx  = {0};
	descPointer_t desc = NULL;
	uint8_t desclen    = 0;

#ifdef	CFG_PHYS_64BIT
#define MAX_DESC_KEY_GEN		8
#else
#define MAX_DESC_KEY_GEN		6
#endif

	ECC_TRACE("Generate Keypair of %d bits", key_size);

	/* Verify first if the curve is supported */
	curve = get_caam_curve(key->curve);
	if (curve == ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job used to prepare the operation */
	desc = caam_alloc_desc(MAX_DESC_KEY_GEN);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/*
	 * Allocate secure and public keys in one buffer
	 * Secure key size = key_size align in bytes
	 * Public key size = (key_size * 2) align in bytes
	 */
	retstatus = caam_alloc_align_buf(&d, (key_size / 8) * 3);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_gen_keypair;
	}

	/* Build the xy buffer to simplify the code */
	xy.data   = d.data + (key_size / 8);
	xy.length = 2 * (key_size / 8);
	xy.paddr  = d.paddr + (key_size / 8);

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	desc_add_word(desc, (PDB_PKGEN_PD1 | PDB_ECC_ECDSEL(curve)));
	desc_add_ptr(desc, d.paddr);
	desc_add_ptr(desc, xy.paddr);
	desc_add_word(desc, PK_KEYPAIR_GEN(ECC));

	desclen = desc_get_len(desc);
	desc_update_hdr(desc, DESC_HEADER_IDX(desclen, (desclen - 1)));

	ECC_DUMPDESC(desc);
	jobctx.desc = desc;
	cache_operation(TEE_CACHEFLUSH, d.data, d.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, d.data, d.length);

		/* Copy all keypair parameters */
		ret = crypto_bignum_bin2bn(d.data, (key_size / 8), key->d);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(xy.data, (xy.length / 2), key->x);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ret = crypto_bignum_bin2bn(xy.data + (xy.length / 2),
						(xy.length / 2), key->y);
		if (ret != TEE_SUCCESS)
			goto exit_gen_keypair;

		ECC_DUMPBUF("D", d.data, (key_size / 8));
		ECC_DUMPBUF("X", xy.data, (xy.length / 2));
		ECC_DUMPBUF("Y", xy.data + (xy.length / 2), (xy.length / 2));

		ret = TEE_SUCCESS;
	} else {
		ECC_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}


exit_gen_keypair:
	caam_free_desc(&desc);
	caam_free_buf(&d);

	return ret;
}

/**
 * @brief   Signature of ECC message
 *
 * @param[in/out]  sdata   ECC data to sign / Signature
 *
 * @note Message to sign is already hashed
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 * @retval TEE_ERROR_GENERIC           Generic error
 */
static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	enum CAAM_Status retstatus;

	enum caam_ecc_curve curve;
	struct ecc_keypair *inkey = sdata->key;
	struct caam_ecc_keypair ecckey = { {0} };

	paddr_t paddr_msg;

	size_t sign_length;

	struct caambuf sign_align = {0};
	int            realloc    = 0;

	struct jr_jobctx jobctx  = {0};
	descPointer_t desc = NULL;
	uint8_t desclen    = 0;

#ifdef	CFG_PHYS_64BIT
#define MAX_DESC_SIGN		13
#else
#define MAX_DESC_SIGN		9
#endif

	ECC_TRACE("ECC Signature");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inkey->curve);
	if (curve == ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Check if the Signature Buffer length:
	 *  - 1st Part: size_sec
	 *  - 2nd Part: size_sec roundup to 16 bytes
	 */
	sign_length = (ROUNDUP(sdata->size_sec, 16) + sdata->size_sec);

	/* Get physical address of the input message */
	paddr_msg = virt_to_phys(sdata->message.data);
	if (!paddr_msg)  {
		ret = TEE_ERROR_GENERIC;
		goto exit_sign;
	}
	ECC_DUMPBUF("Message", sdata->message.data,
					sdata->message.length);

	/*
	 * ReAllocate the signature result buffer with a maximum size
	 * of the roundup to 16 bytes of the secure size in bytes
	 * if not cache aligned
	 */
	realloc = caam_realloc_align(sdata->signature.data,
						&sign_align, sign_length);
	if (realloc == (-1)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_sign;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(MAX_DESC_SIGN);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_sign;
	}

	/* Convert the private key to a local key */
	retstatus = do_keypair_conv(&ecckey, inkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_sign;
	}

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	desc_add_word(desc, PDB_PKSIGN_PD1 | PDB_ECC_ECDSEL(curve));
	/* Secret key */
	desc_add_ptr(desc, ecckey.d.paddr);
	/* Input message */
	desc_add_ptr(desc, paddr_msg);
	/* Signature 1st part */
	desc_add_ptr(desc, sign_align.paddr);
	/* Signature 2nd part */
	desc_add_ptr(desc, (sign_align.paddr + sdata->size_sec));
	/* Message length */
	desc_add_word(desc, sdata->message.length);


	desc_add_word(desc, DSA_SIGN(ECC));

	desclen = desc_get_len(desc);
	desc_update_hdr(desc, DESC_HEADER_IDX(desclen, (desclen - 1)));

	ECC_DUMPDESC(desc);
	jobctx.desc = desc;

	cache_operation(TEE_CACHECLEAN, sdata->message.data,
					sdata->message.length);
	cache_operation(TEE_CACHEFLUSH, sign_align.data, sign_align.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, sign_align.data,
					sign_align.length);

		if (realloc == 1)
			memcpy(sdata->signature.data, sign_align.data,
					2 * sdata->size_sec);

		sdata->signature.length = 2 * sdata->size_sec;

		ECC_DUMPBUF("Signature", sdata->signature.data,
					sdata->signature.length);

		ret = TEE_SUCCESS;
	} else {
		ECC_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}


exit_sign:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);

	if (realloc == 1)
		caam_free_buf(&sign_align);

	return ret;
}

/**
 * @brief   Verification of the Signature of ECC message
 *
 * @param[in/out]  sdata   ECC Signature to verify
 *
 * @note Message to sign is already hashed
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SIGNATURE_INVALID Signature is not valid
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 */
static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	enum CAAM_Status retstatus;

	enum caam_ecc_curve curve;
	struct ecc_public_key *inkey = sdata->key;
	struct caam_ecc_keypair ecckey = { {0} };
	struct caambuf tmp = {0};

	paddr_t paddr_msg;
	paddr_t paddr_sign;

	struct jr_jobctx jobctx  = {0};
	descPointer_t desc = NULL;
	uint8_t desclen    = 0;

#ifdef	CFG_PHYS_64BIT
#define MAX_DESC_VERIFY		15
#else
#define MAX_DESC_VERIFY		10
#endif

	ECC_TRACE("ECC Verify");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inkey->curve);
	if (curve == ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get physical address of the input message */
	paddr_msg = virt_to_phys(sdata->message.data);
	if (!paddr_msg)  {
		ret = TEE_ERROR_GENERIC;
		goto exit_verify;
	}

	/* Get physical address of the signature */
	paddr_sign = virt_to_phys(sdata->signature.data);
	if (!paddr_sign)  {
		ret = TEE_ERROR_GENERIC;
		goto exit_verify;
	}

	/* Allocate a Temporary buffer used by the CAAM */
	retstatus = caam_alloc_align_buf(&tmp, 2 * sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_verify;
	}

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(MAX_DESC_VERIFY);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_verify;
	}

	/* Convert the Public key to local key */
	retstatus = do_keypub_conv(&ecckey, inkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_verify;
	}

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	desc_add_word(desc, PDB_PKVERIFY_PD1 | PDB_ECC_ECDSEL(curve));
	/* Public key */
	desc_add_word(desc, ecckey.xy.paddr);
	/* Input message */
	desc_add_word(desc, paddr_msg);
	/* Signature 1st part */
	desc_add_word(desc, paddr_sign);
	/* Signature 2nd part */
	desc_add_word(desc, (paddr_sign + sdata->size_sec));
	/* Temporary buffer */
	desc_add_word(desc, tmp.paddr);
	/* Message length */
	desc_add_word(desc, sdata->message.length);

	desc_add_word(desc, DSA_VERIFY(ECC));
	desclen = desc_get_len(desc);
	desc_update_hdr(desc, DESC_HEADER_IDX(desclen, (desclen - 1)));

	ECC_DUMPDESC(desc);
	jobctx.desc = desc;

	cache_operation(TEE_CACHECLEAN, sdata->message.data,
					sdata->message.length);
	cache_operation(TEE_CACHECLEAN, sdata->signature.data,
					sdata->signature.length);
	cache_operation(TEE_CACHEFLUSH, tmp.data, tmp.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if ((retstatus == CAAM_JOB_STATUS) && (jobctx.status != 0)) {
		ECC_TRACE("ECC Verify Status 0x%08"PRIx32"", jobctx.status);
		ret = TEE_ERROR_SIGNATURE_INVALID;
	} else if (retstatus != CAAM_NO_ERROR) {
		ECC_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	} else
		ret = TEE_SUCCESS;


exit_verify:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);
	caam_free_buf(&tmp);

	return ret;
}

/**
 * @brief   Compute the shared secret data from ECC Private key \a private_key
 *          and Public Key \a public_key
 *
 * @param[in/out]  sdata   ECC Shared Secret data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_SHORT_BUFFER      Result buffer too short
 */
static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	enum CAAM_Status retstatus;

	enum caam_ecc_curve curve;
	struct ecc_keypair    *inprivkey = sdata->key_priv;
	struct ecc_public_key *inpubkey  = sdata->key_pub;
	struct caam_ecc_keypair ecckey = { {0} };

	struct caambuf secret_align = {0};
	int            realloc    = 0;

	struct jr_jobctx jobctx  = {0};
	descPointer_t desc = NULL;
	uint8_t desclen    = 0;

#ifdef	CFG_PHYS_64BIT
#define MAX_DESC_SHARED		10
#else
#define MAX_DESC_SHARED		7
#endif
	ECC_TRACE("ECC Shared Secret");

	/* Verify first if the curve is supported */
	curve = get_caam_curve(inpubkey->curve);
	if (curve == ECC_UNKNOWN)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate the job descriptor */
	desc = caam_alloc_desc(MAX_DESC_SHARED);
	if (!desc) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/*
	 * ReAllocate the secret result buffer with a maximum size
	 * of the secret size if not cache aligned
	 */
	realloc = caam_realloc_align(sdata->secret.data,
						&secret_align,
						sdata->size_sec);
	if (realloc == (-1)) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/* Convert the Private key to local key */
	retstatus = do_keypair_conv(&ecckey, inprivkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/*Convert the Public key to local key */
	retstatus = do_keypub_conv(&ecckey, inpubkey, sdata->size_sec);
	if (retstatus != CAAM_NO_ERROR) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_shared;
	}

	/*
	 * Build the descriptor using Predifined ECC curve
	 */
	desc_init(desc);
	desc_add_word(desc, DESC_HEADER(0));
	desc_add_word(desc, PDB_SHARED_SECRET_PD1 | PDB_ECC_ECDSEL(curve));
	/* Public key */
	desc_add_ptr(desc, ecckey.xy.paddr);
	/* Private key */
	desc_add_ptr(desc, ecckey.d.paddr);
	/* Output secret */
	desc_add_ptr(desc, secret_align.paddr);

	desc_add_word(desc, SHARED_SECRET(ECC));
	desclen = desc_get_len(desc);
	desc_update_hdr(desc, DESC_HEADER_IDX(desclen, (desclen - 1)));

	ECC_DUMPDESC(desc);
	jobctx.desc = desc;

	cache_operation(TEE_CACHEFLUSH, secret_align.data,
			secret_align.length);
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		cache_operation(TEE_CACHEINVALIDATE, secret_align.data,
			secret_align.length);
		if (realloc == 1)
			memcpy(sdata->secret.data, secret_align.data,
					secret_align.length);

		sdata->secret.length = sdata->size_sec;

		ECC_DUMPBUF("Secret", sdata->secret.data,
					sdata->secret.length);

		ret = TEE_SUCCESS;
	} else {
		ECC_TRACE("CAAM Status 0x%08"PRIx32"", jobctx.status);
		ret = job_status_to_tee_result(jobctx.status);
	}

exit_shared:
	caam_free_desc(&desc);
	do_keypair_free(&ecckey);

	if (realloc == 1)
		caam_free_buf(&secret_align);

	return ret;
}

/**
 * @brief   Registration of the ECC Driver
 */
struct drvcrypt_ecc driver_ecc = {
	.alloc_keypair   = &do_allocate_keypair,
	.alloc_publickey = &do_allocate_publickey,
	.free_publickey  = &do_free_publickey,
	.gen_keypair     = &do_gen_keypair,
	.sign            = &do_sign,
	.verify          = &do_verify,
	.shared_secret   = &do_shared_secret,
};

/**
 * @brief   Initialize the ECC module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 * @retval  CAAM_OUT_MEMORY  Out of memory
 */
enum CAAM_Status caam_ecc_init(vaddr_t ctrl_addr __unused)
{
	enum CAAM_Status retstatus = CAAM_FAILURE;

	if (drvcrypt_register(CRYPTO_ECC, &driver_ecc) == 0)
		retstatus = CAAM_NO_ERROR;

	return retstatus;
}

