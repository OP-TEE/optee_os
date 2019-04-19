/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    caam_hash.h
 *
 * @brief   CAAM Hash manager header.
 */
#ifndef __CAAM_HASH_H__
#define __CAAM_HASH_H__

/**
 * @brief   Initialize the Hash module
 *
 * @param[in] ctrl_addr   Controller base address
 *
 * @retval  CAAM_NO_ERROR    Success
 * @retval  CAAM_FAILURE     An error occurred
 */
enum CAAM_Status caam_hash_init(vaddr_t ctrl_addr);

#endif /* __CAAM_HASH_H__ */

