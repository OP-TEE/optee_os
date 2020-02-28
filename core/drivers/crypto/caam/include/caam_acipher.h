/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   CAAM Asymmetric Cipher manager header.
 */
#ifndef __CAAM_ACIPHER_H__
#define __CAAM_ACIPHER_H__

#include <caam_common.h>

#ifdef CFG_NXP_CAAM_RSA_DRV
/*
 * Initialize the RSA module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_rsa_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_rsa_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_RSA_DRV */

#ifdef CFG_NXP_CAAM_ACIPHER_DRV
/*
 * Initialize the MATH module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_math_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_math_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_ACIPHER_DRV */
#endif /* __CAAM_ACIPHER_H__ */
