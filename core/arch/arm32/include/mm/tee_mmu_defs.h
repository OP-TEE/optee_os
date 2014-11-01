/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TEE_MMU_DEFS_H
#define TEE_MMU_DEFS_H

/* Defined to the smallest possible secondary L1 MMU table */
#define TEE_MMU_TTBCR_N_VALUE		7

/* Number of sections in ttbr0 when user mapping activated */
#define TEE_MMU_UL1_NUM_ENTRIES         ((1 << TEE_MMU_TTBCR_N_VALUE) / 4)

#define TEE_MMU_UL1_SIZE	(TEE_MMU_UL1_NUM_ENTRIES * sizeof(uint32_t))
#define TEE_MMU_UL1_ALIGNMENT	TEE_MMU_UL1_SIZE

/*
 * kmap works in common mapping starting at virtual address just above the
 * per CPU user mapping. kmap has 32 MiB of virtual address space.
 */
#define TEE_MMU_KMAP_OFFS		TEE_MMU_UL1_NUM_ENTRIES
#define TEE_MMU_KMAP_NUM_ENTRIES	32
#define TEE_MMU_KMAP_START_VA		(TEE_MMU_UL1_NUM_ENTRIES << \
					 SECTION_SHIFT)
#define TEE_MMU_KMAP_END_VA		((TEE_MMU_UL1_NUM_ENTRIES + \
					  TEE_MMU_KMAP_NUM_ENTRIES) << \
						SECTION_SHIFT)

#define TEE_MMU_L1_NUM_ENTRIES		(TEE_MMU_L1_SIZE / 4)
#define TEE_MMU_L1_SIZE			(1 << 14)
#define TEE_MMU_L1_ALIGNMENT		TEE_MMU_L1_SIZE

/* TTB attributes */

/* Mask for all attributes */
#define TEE_MMU_TTB_ATTR_MASK	((1 << 7) - 1)
/* TTB0 of TTBR0 (depends on TEE_MMU_TTBCR_N_VALUE) */
#define TEE_MMU_TTB_UL1_MASK	(~(TEE_MMU_UL1_ALIGNMENT - 1))
/* TTB1 of TTBR1 */
#define TEE_MMU_TTB_L1_MASK	(~(TEE_MMU_L1_ALIGNMENT - 1))


/* Sharable */
#define TEE_MMU_TTB_S           (1 << 1)

/* Not Outer Sharable */
#define TEE_MMU_TTB_NOS         (1 << 5)

/* Normal memory, Inner Non-cacheable */
#define TEE_MMU_TTB_IRGN_NC     0

/* Normal memory, Inner Write-Back Write-Allocate Cacheable */
#define TEE_MMU_TTB_IRGN_WBWA   (1 << 6)

/* Normal memory, Inner Write-Through Cacheable */
#define TEE_MMU_TTB_IRGN_WT     1

/* Normal memory, Inner Write-Back no Write-Allocate Cacheable */
#define TEE_MMU_TTB_IRGN_WB     (1 | (1 << 6))

/* Normal memory, Outer Write-Back Write-Allocate Cacheable */
#define TEE_MMU_TTB_RNG_WBWA    (1 << 3)

/*
 * Second-level descriptor Small page table Attributes
 */

/* Small page */
#define TEE_MMU_L2SP_SMALL_PAGE (1 << 1)

/* Execute never */
#define TEE_MMU_L2SP_XN         1

/* Normal memory, Outer Write-Back Write-Allocate Cacheable */
#define TEE_MMU_L2SP_WBWA       ((1 << 6) | (1 << 3) | (1 << 2))

/* Not global */
#define TEE_MMU_L2SP_NG         (1 << 11)

/* Sharable */
#define TEE_MMU_L2SP_S          (1 << 10)

/* Privileged access only */
#define TEE_MMU_L2SP_PRIV_ACC   (1 << 4)

/* Clear access from attribute */
#define TEE_MMU_L2SP_CLEAR_ACC(attr)    ((attr) & ~((1 << 5) | (1 << 4)))

#endif /* TEE_MMU_DEFS_H */
