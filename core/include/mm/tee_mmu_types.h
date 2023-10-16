/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2021, Linaro Limited
 * Copyright (c) 2022, Arm Limited.
 */
#ifndef __MM_TEE_MMU_TYPES_H
#define __MM_TEE_MMU_TYPES_H

#include <stdint.h>
#include <sys/queue.h>
#include <util.h>

#define TEE_MATTR_VALID_BLOCK		BIT(0)
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
#define TEE_MATTR_PROT_MASK	\
		(TEE_MATTR_PRWX | TEE_MATTR_URWX | TEE_MATTR_GUARDED)

#define TEE_MATTR_GLOBAL		BIT(10)
#define TEE_MATTR_SECURE		BIT(11)

#define TEE_MATTR_MEM_TYPE_MASK	U(0x7)
#define TEE_MATTR_MEM_TYPE_SHIFT	U(12)
/* These are shifted TEE_MATTR_MEM_TYPE_SHIFT */

/*
 * Device-nGnRnE most restrictive (equivalent to Strongly Ordered memory
 * in the ARMv7 architecture).
 * https://developer.arm.com/documentation/den0024/a/Memory-Ordering/Memory-types/Device-memory
 *
 * If an ARMv7 architecture operating system runs on a Cortex-A53 processor,
 * the Device memory type matches the nGnRE encoding and the Strongly-Ordered
 * memory type matches the nGnRnE memory type.
 * https://developer.arm.com/documentation/den0024/a/Memory-Ordering/Memory-types/Device-memory
 */
#define TEE_MATTR_MEM_TYPE_DEV	        U(0) /* Device-nGnRE */
#define TEE_MATTR_MEM_TYPE_CACHED	U(1)
#define TEE_MATTR_MEM_TYPE_STRONGLY_O	U(2) /* Device-nGnRnE  */
#define TEE_MATTR_MEM_TYPE_TAGGED	U(3)

#define TEE_MATTR_GUARDED		BIT(15)

/*
 * Tags TA mappings which are only used during a single call (open session
 * or invoke command parameters).
 */
#define VM_FLAG_EPHEMERAL		BIT(0)
/*
 * Tags TA mappings that must not be removed (kernel mappings while in user
 * mode).
 */
#define VM_FLAG_PERMANENT		BIT(1)
/* Tags TA mappings that may be shared with other TAs. */
#define VM_FLAG_SHAREABLE		BIT(2)
/* Tags temporary mappings added to load the ldelf binary */
#define VM_FLAG_LDELF			BIT(3)
/*
 * The mapping should only be mapped read-only, not enforced by the vm_*
 * functions.
 */
#define VM_FLAG_READONLY		BIT(4)

/*
 * Set of flags used by tee_mmu_is_vbuf_inside_ta_private() and
 * tee_mmu_is_vbuf_intersect_ta_private() to tell if a certain region is
 * mapping TA internal memory or not.
 */
#define VM_FLAGS_NONPRIV		(VM_FLAG_EPHEMERAL | \
					 VM_FLAG_PERMANENT | \
					 VM_FLAG_SHAREABLE)

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
	uint16_t attr; /* TEE_MATTR_* above */
	uint16_t flags; /* VM_FLAGS_* above */
	TAILQ_ENTRY(vm_region) link;
};

enum vm_paged_region_type {
	PAGED_REGION_TYPE_RO,
	PAGED_REGION_TYPE_RW,
	PAGED_REGION_TYPE_LOCK,
};

struct vm_paged_region {
	struct fobj *fobj;
	size_t fobj_pgoffs;
	enum vm_paged_region_type type;
	uint32_t flags;
	vaddr_t base;
	size_t size;
	struct pgt **pgt_array;
	TAILQ_ENTRY(vm_paged_region) link;
	TAILQ_ENTRY(vm_paged_region) fobj_link;
};

TAILQ_HEAD(vm_paged_region_head, vm_paged_region);
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

static inline bool mattr_is_cached(uint32_t mattr)
{
	uint32_t mem_type = (mattr >> TEE_MATTR_MEM_TYPE_SHIFT) &
			    TEE_MATTR_MEM_TYPE_MASK;

	return mem_type == TEE_MATTR_MEM_TYPE_CACHED ||
	       mem_type == TEE_MATTR_MEM_TYPE_TAGGED;
}
#endif
