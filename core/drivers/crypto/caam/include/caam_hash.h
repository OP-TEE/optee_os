/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Hash manager header.
 */
#ifndef __CAAM_HASH_H__
#define __CAAM_HASH_H__

#ifdef CFG_NXP_CAAM_HASH_DRV
/*
 * Initialize the Hash module
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_hash_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_hash_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif

#endif /* __CAAM_HASH_H__ */
