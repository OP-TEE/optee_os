// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    huk.c
 *
 * @brief   Crypto HUK interface implementation to enable HW driver.
 */

/* Driver Crypto includes */
#include <crypto_extension.h>
#include <drvcrypt_huk.h>

/**
 * @brief   Generation of the Hardware Unique Key (HUK)
 *
 * @param[out] huk  HUK key generated
 *
 * @retval TEE_SUCCESS                 Success
 * @retval TEE_ERROR_OUT_OF_MEMORY     Out of memory
 * @retval TEE_ERROR_BAD_PARAMETERS    Bad parameters
 * @retval TEE_ERROR_NOT_IMPLEMENTED   Algorithm is not implemented
 * @retval TEE_ERROR_GENERIC           Generic error
 */
TEE_Result crypto_generate_huk(struct drvcrypt_buf *huk)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_huk *hukdrv;

	if (!huk) {
		CRYPTO_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!huk->data) {
		CRYPTO_TRACE("Input parameters reference error");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	hukdrv = drvcrypt_getmod(CRYPTO_HUK);
	if (hukdrv) {
		if (hukdrv->generate_huk)
			ret = hukdrv->generate_huk(huk);
	}

	CRYPTO_TRACE("Generate HUK returned 0x%"PRIx32"", ret);
	return ret;
}


