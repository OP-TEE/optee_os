// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2020 NXP
 *
 * RSA Mask Generation function implementation.
 */
#include <drvcrypt.h>
#include <malloc.h>
#include <string.h>
#include <utee_defines.h>

#include "local.h"

TEE_Result drvcrypt_rsa_mgf1(struct drvcrypt_rsa_mgf *mgf_data)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	void *ctx = NULL;
	size_t lastBlock_size = 0;
	size_t nbBlock = 0;
	uint32_t counter = 0;
	uint32_t swapcount = 0;
	uint8_t *cur_mask = mgf_data->mask.data;
	uint8_t *tmpdigest = NULL;

	CRYPTO_TRACE("Generate Mask (%zu bytes) with seed of %zu bytes",
		     mgf_data->mask.length, mgf_data->seed.length);

	/* Calculate the number of complet hash digest */
	lastBlock_size = mgf_data->mask.length % mgf_data->digest_size;
	if (lastBlock_size) {
		/* Allocate a digest buffer for the last block */
		tmpdigest = calloc(1, mgf_data->digest_size);
		if (!tmpdigest)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate the Hash Context */
	ret = crypto_hash_alloc_ctx(&ctx, mgf_data->hash_algo);
	if (ret != TEE_SUCCESS)
		goto exit_mgf;

	nbBlock = (mgf_data->mask.length - lastBlock_size) /
		  mgf_data->digest_size;

	CRYPTO_TRACE("Nb Loop (%zu bytes) = %zu, last Block = %zu bytes",
		     mgf_data->digest_size, nbBlock, lastBlock_size);

	for (; counter < nbBlock;
	     counter++, cur_mask += mgf_data->digest_size) {
		swapcount = TEE_U32_TO_BIG_ENDIAN(counter);

		ret = crypto_hash_init(ctx);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, mgf_data->seed.data,
					 mgf_data->seed.length);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, (uint8_t *)&swapcount,
					 sizeof(swapcount));
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_final(ctx, cur_mask, mgf_data->digest_size);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;
	}

	if (lastBlock_size) {
		CRYPTO_TRACE("Last Block = %zu bytes", lastBlock_size);

		swapcount = TEE_U32_TO_BIG_ENDIAN(counter);

		ret = crypto_hash_init(ctx);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, mgf_data->seed.data,
					 mgf_data->seed.length);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_update(ctx, (uint8_t *)&swapcount,
					 sizeof(swapcount));
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		ret = crypto_hash_final(ctx, tmpdigest, mgf_data->digest_size);
		if (ret != TEE_SUCCESS)
			goto exit_mgf;

		memcpy(cur_mask, tmpdigest, lastBlock_size);
	}

	ret = TEE_SUCCESS;

exit_mgf:
	crypto_hash_free_ctx(ctx);
	free(tmpdigest);

	CRYPTO_TRACE("return 0x%08" PRIx32, ret);
	return ret;
}
