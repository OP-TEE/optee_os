// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    imx_huk.c
 *
 * @brief   i.MX Hardware Unique Key generation.\n
 *          Call CAAM operation to generate the key derived
 *          from the master key
 */
/* Standard includes */
#include <string.h>

/* Global includes */
#include <kernel/tee_common_otp.h>
#include <utee_defines.h>

/* Platform includes */
#include <imx.h>

/* Crypto API Extension includes */
#include <crypto_extension.h>

/* Local includes */

/**
 * @brief   Return a HW unique key value.\n
 *          On i.MX device, return a derivation of the Master Key
 *          by calling the CAAM Blob master key verification
 *          operation using a key modifier corresponding of the
 *          first 16 bytes of the Die ID
 *
 * @param[out] hwhuk  HW Unique key
 */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwhuk)
{
	TEE_Result ret;

	struct drvcrypt_buf cryptohuk = {0};

	/* Initialize the HUK value */
	memset(hwhuk->data, 0, sizeof(hwhuk->data));

	cryptohuk.length = sizeof(hwhuk->data);
	cryptohuk.data   = hwhuk->data;

	ret = crypto_generate_huk(&cryptohuk);

	/*
	 * If there is an error during the Master key derivation, let the device
	 * booting with a 0's key
	 */
	if (ret != TEE_SUCCESS) {
		memset(hwhuk->data, 0, sizeof(hwhuk->data));
		ret = TEE_SUCCESS;
	}

	return ret;
}

