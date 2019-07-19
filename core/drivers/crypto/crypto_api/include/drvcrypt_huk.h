/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    drvcrypt_huk.h
 *
 * @brief   HUK interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_HUK_H__
#define __DRVCRYPT_HUK_H__

#include <tee_api_types.h>

/**
 * @brief   Crypto Library HUK driver operations
 *
 */
struct drvcrypt_huk {
	///< Allocates of the Software context
	TEE_Result (*generate_huk)(struct drvcrypt_buf *hukkey);
};

#endif /* __DRVCRYPT_HUK_H__ */
