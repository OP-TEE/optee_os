/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TEE_MMU_TYPES_H
#define TEE_MMU_TYPES_H

#include <stdint.h>
#include <sys/queue.h>
#include <util.h>

#define TEE_MATTR_VALID_BLOCK		BIT(0)
#define TEE_MATTR_HIDDEN_BLOCK		BIT(1)
#define TEE_MATTR_HIDDEN_DIRTY_BLOCK	BIT(2)
#define TEE_MATTR_TABLE			BIT(3)
#define TEE_MATTR_PR			BIT(4)
#define TEE_MATTR_PW			BIT(5)
#define TEE_MATTR_PX			BIT(6)
#define TEE_MATTR_PRW			(TEE_MATTR_PR | TEE_MATTR_PW)
#define TEE_MATTR_PRX			(TEE_MATTR_PR | TEE_MATTR_PX)
#define TEE_MATTR_PRWX			(TEE_MATTR_PRW | TEE_MATTR_PX)
#define TEE_MATTR_UR			BIT(7)
#define TEE_MATTR_UW			BIT(8)
#define TEE_MATTR_UX			BIT(9)
#define TEE_MATTR_URW			(TEE_MATTR_UR | TEE_MATTR_UW)
#define TEE_MATTR_URX			(TEE_MATTR_UR | TEE_MATTR_UX)
#define TEE_MATTR_URWX			(TEE_MATTR_URW | TEE_MATTR_UX)
#define TEE_MATTR_PROT_MASK		(TEE_MATTR_PRWX | TEE_MATTR_URWX)

#define TEE_MATTR_GLOBAL		BIT(10)
#define TEE_MATTR_SECURE		BIT(11)

#define TEE_MATTR_CACHE_MASK	0x7
#define TEE_MATTR_CACHE_SHIFT	12
/* These are shifted TEE_MATTR_CACHE_SHIFT */
#define TEE_MATTR_CACHE_NONCACHE 0
#define TEE_MATTR_CACHE_CACHED	1

#define TEE_MATTR_LOCKED		BIT(15)
/*
 * Tags TA mappings which are only used during a single call (open session
 * or invoke command parameters).
 */
#define TEE_MATTR_EPHEMERAL		BIT(16)
/*
 * Tags TA mappings that must not be removed (kernel mappings while in user
 * mode).
 */
#define TEE_MATTR_PERMANENT		BIT(17)

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
#define TEE_MMU_UMAP_KCODE_IDX	0
#define TEE_MMU_UMAP_STACK_IDX	1
#else
#define TEE_MMU_UMAP_STACK_IDX	0
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/
#define TEE_MMU_UMAP_CODE_IDX	(TEE_MMU_UMAP_STACK_IDX + 1)
#define TEE_MMU_UMAP_NUM_CODE_SEGMENTS	3

#define TEE_MMU_UMAP_PARAM_IDX		(TEE_MMU_UMAP_CODE_IDX + \
					 TEE_MMU_UMAP_NUM_CODE_SEGMENTS)
#define TEE_MMU_UMAP_MAX_ENTRIES	(TEE_MMU_UMAP_PARAM_IDX + \
					 TEE_NUM_PARAMS)

struct tee_mmap_region {
	unsigned int type; /* enum teecore_memtypes */
	unsigned int region_size;
	paddr_t pa;
	vaddr_t va;
	size_t size;
	uint32_t attr; /* TEE_MATTR_* above */
};

struct vm_region {
	struct mobj *mobj;
	size_t offset;
	vaddr_t va;
	size_t size;
	uint32_t attr; /* TEE_MATTR_* above */
	TAILQ_ENTRY(vm_region) link;
};

TAILQ_HEAD(vm_region_head, vm_region);

struct vm_info {
	struct vm_region_head regions;
	unsigned int asid;
};

static inline void mattr_perm_to_str(char *str, size_t size, uint32_t attr)
{
	if (size < 7)
		return;

	str[0] = (attr & TEE_MATTR_UR) ? 'r' : '-';
	str[1] = (attr & TEE_MATTR_UW) ? 'w' : '-';
	str[2] = (attr & TEE_MATTR_UX) ? 'x' : '-';
	str[3] = (attr & TEE_MATTR_PR) ? 'R' : '-';
	str[4] = (attr & TEE_MATTR_PW) ? 'W' : '-';
	str[5] = (attr & TEE_MATTR_PX) ? 'X' : '-';
	str[6] = '\0';
}

#endif
