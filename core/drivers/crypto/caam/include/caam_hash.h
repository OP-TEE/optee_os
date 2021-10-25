/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2021 NXP
 *
 * Brief   CAAM Hash manager header.
 */
#ifndef __CAAM_HASH_H__
#define __CAAM_HASH_H__

#include <caam_jr.h>

#ifdef CFG_NXP_CAAM_HASH_DRV
/*
 * Initialize the Hash module
 *
 * @caam_jrcfg	JR configuration structure
 */
enum caam_status caam_hash_init(struct caam_jrcfg *caam_jrcfg);
#else
static inline enum caam_status
caam_hash_init(struct caam_jrcfg *caam_jrcfg __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_HASH_DRV */

#ifdef CFG_NXP_CAAM_HMAC_DRV
/*
 * Initialize the HMAC module
 *
 * @caam_jrcfg	JR configuration structure
 */
enum caam_status caam_hmac_init(struct caam_jrcfg *caam_jrcfg);
#else
static inline enum caam_status
caam_hmac_init(struct caam_jrcfg *caam_jrcfg __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_HMAC_DRV */
#endif /* __CAAM_HASH_H__ */
