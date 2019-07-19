// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    rsamgf.c
 *
 * @brief   RSA Mask Generation function implementation.
 */

/* Global includes */
#include <malloc.h>
#include <string.h>
#include <utee_defines.h>

/* Driver Crypto includes */
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>

/* Local includes */
#include "local.h"

/**
 * @brief   Mask Generation function. Use a Hash operation
 *          to generate an output \a mask from a input \a seed
 *
 * @param[in/out] mgf_data  MGF data
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result rsa_mgf1(struct drvcrypt_rsa_mgf *mgf_data)
{
	TEE_Result ret;

	void     *ctx = NULL;
	size_t   lastBlock_size;
	size_t   nbBlock = 0;
	uint32_t counter = 0;
	uint32_t swapcount;
	uint8_t  *cur_mask = mgf_data->mask.data;
	uint8_t  *tmpdigest = NULL;


	CRYPTO_TRACE("Generate Mask (%d bytes) with seed of %d bytes",
			mgf_data->mask.length, mgf_data->seed.length);

	/* Calculate the number of complet hash digest*/
	lastBlock_size = mgf_data->mask.length % mgf_data->digest_size;
	if (lastBlock_size) {
		/* Allocate a digest buffer for the last block */
		tmpdigest = malloc(mgf_data->digest_size);
		if (!tmpdigest)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the Hash Context */
	ret = crypto_hash_alloc_ctx(&ctx, mgf_data->hash_algo);
	if (ret != TEE_SUCCESS)
		goto exit_mgf;

	nbBlock = (mgf_data->mask.length - lastBlock_size) /
	    mgf_data->digest_size;

	CRYPTO_TRACE("Nb Loop (%d bytes) = %d, last Block = %d byes",
		mgf_data->digest_size, nbBlock, lastBlock_size);

	for (counter = 0; counter < nbBlock; counter++,
		cur_mask += mgf_data->digest_size) {

		swapcount = TEE_U32_TO_BIG_ENDIAN(counter);

		ret = crypto_hash_init(ctx, mgf_data->hash_algo);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, mgf_data->hash_algo,
				mgf_data->seed.data, mgf_data->seed.length);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, mgf_data->hash_algo,
				(uint8_t *)&swapcount, sizeof(swapcount));
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_final(ctx, mgf_data->hash_algo,
				cur_mask, mgf_data->digest_size);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;
	}

	if (lastBlock_size) {
		CRYPTO_TRACE("Last Block = %d bytes", lastBlock_size);

		swapcount = TEE_U32_TO_BIG_ENDIAN(counter);

		ret = crypto_hash_init(ctx, mgf_data->hash_algo);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, mgf_data->hash_algo,
				mgf_data->seed.data, mgf_data->seed.length);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, mgf_data->hash_algo,
				(uint8_t *)&swapcount, sizeof(swapcount));
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_final(ctx, mgf_data->hash_algo,
				tmpdigest, mgf_data->digest_size);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		memcpy(cur_mask, tmpdigest, lastBlock_size);
	}

	ret = TEE_SUCCESS;

exit_mgf:
	crypto_hash_free_ctx(ctx, mgf_data->hash_algo);
	free(tmpdigest);

	CRYPTO_TRACE("ret 0x%08"PRIx32"", ret);
	return ret;
}

