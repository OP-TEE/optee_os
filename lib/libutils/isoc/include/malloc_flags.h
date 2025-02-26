/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Linaro Limited.
 */
#ifndef __MALLOC_FLAGS_H
#define __MALLOC_FLAGS_H

/*
 * This file doesn't have any dependencies to minimize impact when
 * including this file.
 *
 * Pulling in for instance <util.h> for the BIT() macro would also define
 * the MIN() macro which would cause a error in
 * core/lib/libtomcrypt/src/pk/dsa/dsa_decrypt_key.c
 */

/*
 * Memory allocation flags to control how buffers are allocated. Flags may
 * be ignored depending on configuration or if they don't apply. These
 * flags are primarily used by malloc() and friends in malloc.h, but can be
 * extended with flags that only mean something for other functions to
 * avoid needless translation of one class of flags to another class of
 * flags.
 */
#define MAF_NULL	0x00	/* Passed if no flags are needed */
#define MAF_ZERO_INIT	0x01	/* Zero initialize the allocated buffer */
#define MAF_NEX		0x02	/* Allocate from nexus heap */
#define MAF_FREE_WIPE	0x04	/* Free wipes allocated buffer */
/*
 * Used by tee_mm_init() to indicatate that the pool should allocate
 * from high address to low address.
 */
#define MAF_HI_ALLOC	0x10
/*
 * Used by phys_mem_alloc_flags() to indicate whether physical memory
 * should be allocated from the Core or TA physical memory pool.
 */
#define MAF_CORE_MEM	0x20
/*
 * Used by virt_page_alloc() to inidicate whether the allocated memory
 * should by guarded by an unmapped page at the beginning and end.
 */
#define MAF_GUARD_HEAD	0x40
#define MAF_GUARD_TAIL	0x80

#endif /*__MALLOC_FLAGS_H*/
