/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Configuration header.
 */
#ifndef __CAAM_HAL_CFG_H__
#define __CAAM_HAL_CFG_H__

#include <caam_jr.h>

/*
 * Returns the Job Ring Configuration to be used by the TEE
 *
 * @jrcfg   [out] Job Ring Configuration
 *
 * Returns:
 * CAAM_NO_ERROR   Success
 * CAAM_FAILURE    An error occurred
 */
enum CAAM_Status caam_hal_cfg_get_conf(struct caam_jrcfg *jrcfg);

/*
 * Setup the Non-Secure Job Ring
 *
 * @ctrl_base   Virtual CAAM Controller Base address
 */
void caam_hal_cfg_setup_nsjobring(vaddr_t ctrl_base);

#endif /* __CAAM_HAL_CFG_H__ */
