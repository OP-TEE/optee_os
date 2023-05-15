/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef __KERNEL_HUK_SUBKEY_H
#define __KERNEL_HUK_SUBKEY_H

#include <tee_api_types.h>
#include <types_ext.h>
#include <utee_defines.h>

/*
 * enum huk_subkey_usage - subkey usage identifier
 * @HUK_SUBKEY_RPMB:	  RPMB key
 * @HUK_SUBKEY_SSK:	  Secure Storage key
 * @HUK_SUBKEY_DIE_ID:	  Representing the die ID
 * @HUK_SUBKEY_UNIQUE_TA: TA unique key
 * @HUK_SUBKEY_TA_ENC:    TA encryption key
 * @HUK_SUBKEY_SE050:     SCP03 set of encryption keys
 *
 * Add more identifiers as needed, be careful to not change the already
 * assigned numbers as that will affect the derived subkey.
 */
enum huk_subkey_usage {
	/*
	 * All IDs are explicitly assigned to make it easier to keep then
	 * constant.
	 */
	HUK_SUBKEY_RPMB = 0,
	HUK_SUBKEY_SSK = 1,
	HUK_SUBKEY_DIE_ID = 2,
	HUK_SUBKEY_UNIQUE_TA = 3,
	HUK_SUBKEY_TA_ENC = 4,
	HUK_SUBKEY_SE050 = 5,
};

#define HUK_SUBKEY_MAX_LEN	TEE_SHA256_HASH_SIZE

/*
 * huk_subkey_derive() - Derive a subkey from the hardware unique key
 * @usage:		Intended usage of the subkey
 * @const_data:		Constant data to generate different subkeys with
 *			the same usage
 * @const_data_len:	Length of constant data
 * @subkey:		Generated subkey
 * @subkey_len:		Required size of the subkey, sizes larger than
 *			HUK_SUBKEY_MAX_LEN are not accepted.
 *
 * Returns a subkey derived from the hardware unique key. Given the same
 * input the same subkey is returned each time.
 *
 * Return TEE_SUCCES on success or an error code on failure.
 */
TEE_Result huk_subkey_derive(enum huk_subkey_usage usage,
			     const void *const_data, size_t const_data_len,
			     uint8_t *subkey, size_t subkey_len);


#endif /*__KERNEL_HUK_SUBKEY_H*/
