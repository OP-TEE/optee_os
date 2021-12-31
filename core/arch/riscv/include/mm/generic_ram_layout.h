/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright 2022 NXP
 */

#ifndef __MM_GENERIC_RAM_LAYOUT_H
#define __MM_GENERIC_RAM_LAYOUT_H

#include <util.h>

/*
 * Generic RAM layout configuration directives
 *
 * Mandatory directives:
 * CFG_TDDRAM_START
 * CFG_TDDRAM_SIZE
 * CFG_SHMEM_START
 * CFG_SHMEM_SIZE
 *
 * Optional directives:
 * CFG_TEE_LOAD_ADDR	If defined sets TEE_LOAD_ADDR. If not, TEE_LOAD_ADDR
 *			is set by the platform or defaults to TEE_RAM_START.
 * CFG_TEE_RAM_VA_SIZE	Some platforms may have specific needs
 *
 * Optional directives when pager is enabled:
 * CFG_TDSRAM_START	If no set, emulated at CFG_TDDRAM_START
 * CFG_TDSRAM_SIZE	Default to CFG_CORE_TDSRAM_EMUL_SIZE
 *
 * Optional directive when CFG_SECURE_DATA_PATH is enabled:
 * CFG_TEE_SDP_MEM_SIZE	If CFG_TEE_SDP_MEM_BASE is not defined, SDP test
 *			memory byte size can be set by CFG_TEE_SDP_MEM_SIZE.
 *
 * This header file produces the following generic macros upon the mandatory
 * and optional configuration directives listed above:
 *
 * TEE_RAM_START	TEE core RAM physical base address
 * TEE_RAM_VA_SIZE	TEE core virtual memory address range size
 * TEE_RAM_PH_SIZE	TEE core physical RAM byte size
 * TA_RAM_START		TA contexts/pagestore RAM physical base address
 * TA_RAM_SIZE		TA contexts/pagestore RAM byte size
 * TEE_SHMEM_START	Non-secure static shared memory physical base address
 * TEE_SHMEM_SIZE	Non-secure static shared memory byte size
 *
 * TDDRAM_BASE		Main/external secure RAM base address
 * TDDRAM_SIZE		Main/external secure RAM byte size
 * TDSRAM_BASE		On-chip secure RAM base address, required by pager.
 * TDSRAM_SIZE		On-chip secure RAM byte size, required by pager.
 *
 * TEE_LOAD_ADDR	Only defined here if CFG_TEE_LOAD_ADDR is defined.
 *			Otherwise we expect the platform_config.h to define it
 *			unless which LEE_LOAD_ADDR defaults to TEE_RAM_START.
 *
 * TEE_RAM_VA_SIZE	Set to CFG_TEE_RAM_VA_SIZE or defaults to
 *			CORE_MMU_PGDIR_SIZE.
 *
 * TEE_SDP_TEST_MEM_BASE Define if a SDP memory pool is required and none set.
 *			 Always defined in the inner top (high addresses)
 *			 of CFG_TDDRAM_START/_SIZE.
 * TEE_SDP_TEST_MEM_SIZE Set to CFG_TEE_SDP_MEM_SIZE or a default size.
 *
 * ----------------------------------------------------------------------------
 * TEE RAM layout without CFG_WITH_PAGER
 *_
 *  +----------------------------------+ <-- CFG_TDDRAM_START
 *  | TEE core secure RAM (TEE_RAM)    |
 *  +----------------------------------+
 *  | Trusted Application RAM (TA_RAM) |
 *  +----------------------------------+
 *  | SDP test memory (optional)       |
 *  +----------------------------------+ <-- CFG_TDDRAM_START + CFG_TDDRAM_SIZE
 *
 *  +----------------------------------+ <-- CFG_SHMEM_START
 *  | Non-secure static SHM            |
 *  +----------------------------------+ <-- CFG_SHMEM_START + CFG_SHMEM_SIZE
 *
 * ----------------------------------------------------------------------------
 * TEE RAM layout with CFG_WITH_PAGER=y and undefined CFG_TDSRAM_START/_SIZE
 *
 *  +----------------------------------+ <-- CFG_TDDRAM_START
 *  | TEE core secure RAM (TEE_RAM)    |   | | CFG_CORE_TDSRAM_EMUL_SIZE
 *  +----------------------------------+ --|-'
 *  |   reserved (for kasan)           |   | TEE_RAM_VA_SIZE
 *  +----------------------------------+ --'
 *  | TA RAM / Pagestore (TA_RAM)      |
 *  +----------------------------------+ <---- align with CORE_MMU_PGDIR_SIZE
 *  +----------------------------------+ <--
 *  | SDP test memory (optional)       |   | CFG_TEE_SDP_MEM_SIZE
 *  +----------------------------------+ <-+ CFG_TDDRAM_START + CFG_TDDRAM_SIZE
 *
 *  +----------------------------------+ <-- CFG_SHMEM_START
 *  | Non-secure static SHM            |   |
 *  +----------------------------------+   v CFG_SHMEM_SIZE
 *
 * ----------------------------------------------------------------------------
 * TEE RAM layout with CFG_WITH_PAGER=y and define CFG_TDSRAM_START/_SIZE
 *
 *  +----------------------------------+ <-- CFG_TDSRAM_START
 *  | TEE core secure RAM (TEE_RAM)    |   | CFG_TDSRAM_SIZE
 *  +----------------------------------+ --'
 *
 *  +----------------------------------+  <- CFG_TDDRAM_START
 *  | TA RAM / Pagestore (TA_RAM)      |
 *  |----------------------------------+ <---- align with CORE_MMU_PGDIR_SIZE
 *  |----------------------------------+ <--
 *  | SDP test memory (optional)       |   | CFG_TEE_SDP_MEM_SIZE
 *  +----------------------------------+ <-+ CFG_TDDRAM_START + CFG_TDDRAM_SIZE
 *
 *  +----------------------------------+ <-- CFG_SHMEM_START
 *  | Non-secure static SHM            |   |
 *  +----------------------------------+   v CFG_SHMEM_SIZE
 */

#ifdef CFG_TEE_LOAD_ADDR
#define TEE_LOAD_ADDR		CFG_TEE_LOAD_ADDR
#else
/* Platform specific platform_config.h may set TEE_LOAD_ADDR */
#endif

#ifdef CFG_TEE_RAM_VA_SIZE
#define TEE_RAM_VA_SIZE		CFG_TEE_RAM_VA_SIZE
#else
#define TEE_RAM_VA_SIZE		CORE_MMU_PGDIR_SIZE
#endif

#ifdef CFG_SHMEM_SIZE
#define TEE_SHMEM_SIZE		CFG_SHMEM_SIZE
#endif

#ifdef CFG_SHMEM_START
#define TEE_SHMEM_START		CFG_SHMEM_START
#ifndef CFG_SHMEM_SIZE
#error CFG_SHMEM_START mandates CFG_SHMEM_SIZE
#endif
#endif

#if defined(CFG_TDSRAM_START)
#define TDSRAM_BASE		CFG_TDSRAM_START
#define TDSRAM_SIZE		CFG_TDSRAM_SIZE
#endif

#ifdef CFG_TDDRAM_START
#if !defined(CFG_WITH_PAGER) || defined(CFG_TDSRAM_START)
#define TDDRAM_BASE		CFG_TDDRAM_START
#define TDDRAM_SIZE		CFG_TDDRAM_SIZE
#else
#define TDSRAM_BASE		CFG_TDDRAM_START
#define TDSRAM_SIZE		CFG_CORE_TDSRAM_EMUL_SIZE
#define TDDRAM_BASE		ROUNDUP(TDSRAM_BASE + TDSRAM_SIZE, \
					TEE_RAM_VA_SIZE)
#define TDDRAM_SIZE		(CFG_TDDRAM_START + (CFG_TDDRAM_SIZE - \
					TDDRAM_BASE))
#endif

#ifdef CFG_WITH_PAGER
#define TEE_RAM_START		TDSRAM_BASE
#define TEE_RAM_PH_SIZE		TDSRAM_SIZE
#define TA_RAM_START		ROUNDUP(TDDRAM_BASE, CORE_MMU_PGDIR_SIZE)
#else
#define TEE_RAM_START		TDDRAM_BASE
#define TEE_RAM_PH_SIZE		TEE_RAM_VA_SIZE
#define TA_RAM_START		ROUNDUP(TDDRAM_BASE + TEE_RAM_VA_SIZE, \
					SMALL_PAGE_SIZE)
#endif /*CFG_WITH_PAGER*/

#define TA_RAM_SIZE		(ROUNDDOWN(TDDRAM_BASE + (TDDRAM_SIZE - \
					  TEE_SDP_TEST_MEM_SIZE), \
					  SMALL_PAGE_SIZE) - TA_RAM_START)
#endif /*CFG_TDDRAM_START*/

/*
 * Secure data path test memory pool
 * - If SDP is disabled, no SDP test memory needed.
 * - If SDP is enabled, if CFG_TEE_SDP_MEM_BASE, SDP test pool is not needed.
 * - If SDP is enabled and CFG_TEE_SDP_MEM_BASE not defined, a SDP test pool
 *   is defined at the end of the secure RAM. CFG_TEE_SDP_MEM_SIZE can set
 *   its size otherwise it defaults to 4MB.
 */
#if !defined(CFG_SECURE_DATA_PATH) || defined(CFG_TEE_SDP_MEM_BASE)
#define TEE_SDP_TEST_MEM_SIZE		0
#else
#ifdef CFG_TEE_SDP_MEM_SIZE
#define TEE_SDP_TEST_MEM_SIZE		CFG_TEE_SDP_MEM_SIZE
#else
#define TEE_SDP_TEST_MEM_SIZE		SIZE_4M
#endif
#define TEE_SDP_TEST_MEM_BASE		(CFG_TDDRAM_START + (CFG_TDDRAM_SIZE - \
						TEE_SDP_TEST_MEM_SIZE))
#endif

#endif /*__MM_GENERIC_RAM_LAYOUT_H*/
