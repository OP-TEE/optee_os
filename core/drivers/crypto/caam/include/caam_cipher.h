/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018-2019 NXP
 *
 * @file    caam_cipher.h
 *
 * @brief   CAAM Cipher manager header.
 */
#ifndef __CAAM_CIPHER_H__
#define __CAAM_CIPHER_H__

/* Global Common includes */
#include <types_ext.h>

/**
 * @brief   Initialize the Cipher module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 */
enum CAAM_Status caam_cipher_init(vaddr_t ctrl_addr);

#endif /* __CAAM_CIPHER_H__ */

