/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   CAAM Cipher manager header.
 */
#ifndef __CAAM_CIPHER_H__
#define __CAAM_CIPHER_H__

#include <caam_common.h>

#ifdef CFG_NXP_CAAM_CIPHER_DRV
/*
 * Initialize the Cipher module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_cipher_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_cipher_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_CIPHER_DRV */
#ifdef CFG_NXP_CAAM_CMAC_DRV
/*
 * Initialize the CMAC module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_cmac_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_cmac_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_CMAC_DRV */
#endif /* __CAAM_CIPHER_H__ */
