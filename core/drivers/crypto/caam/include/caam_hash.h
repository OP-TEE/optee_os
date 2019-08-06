/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Hash manager header.
 */
#ifndef __CAAM_HASH_H__
#define __CAAM_HASH_H__

/*
 * Initialize the Hash module
 *
 * @ctrl_addr   Controller base address
 */
enum CAAM_Status caam_hash_init(vaddr_t ctrl_addr);

#endif /* __CAAM_HASH_H__ */
