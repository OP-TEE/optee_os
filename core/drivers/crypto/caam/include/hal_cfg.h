/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    hal_cfg.h
 *
 * @brief   CAAM Configuration header.
 */
#ifndef __HAL_CFG_H__
#define __HAL_CFG_H__

/**
 * @brief   Returns the Job Ring Configuration to be used by the TEE
 *
 * @param[out] jr_cfg   Job Ring Configuration
 *
 * @retval  CAAM_NO_ERROR   Success
 * @retval  CAAM_FAILURE    An error occurred
 */
enum CAAM_Status hal_cfg_get_conf(struct jr_cfg *jr_cfg);

/**
 * @brief   Setup the Non-Secure Job Ring
 *
 * @param[in] ctrl_base   Virtual CAAM Controller Base address
 *
 */
void hal_cfg_setup_nsjobring(vaddr_t ctrl_base);

#endif /* __HAL_CFG_H__ */
