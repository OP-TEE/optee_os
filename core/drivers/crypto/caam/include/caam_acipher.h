/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   CAAM Asymmetric Cipher manager header.
 */
#ifndef __CAAM_ACIPHER_H__
#define __CAAM_ACIPHER_H__

#include <caam_common.h>
#include <caam_jr.h>

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

#ifdef CFG_NXP_CAAM_DH_DRV
/*
 * Initialize the DH module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_dh_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_dh_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_DH_DRV */

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

#ifdef CFG_NXP_CAAM_ECC_DRV
/*
 * Initialize the Cipher module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_ecc_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_ecc_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_ECC_DRV */

#ifdef CFG_NXP_CAAM_DSA_DRV
/*
 * Initialize the DSA module
 *
 * @caam_jrcfg   CAAM job ring configuration
 */
enum caam_status caam_dsa_init(struct caam_jrcfg *caam_jrcfg);
#else
static inline enum caam_status
caam_dsa_init(struct caam_jrcfg *caam_jrcfg __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_DSA_DRV */
#endif /* __CAAM_ACIPHER_H__ */
