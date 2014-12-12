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
#ifndef TEE_ARMV7_MMU_H
#define TEE_ARMV7_MMU_H

/*
 * MMU table section flags
 */
#define TEE_MMU_SECTION_ATTR_MASK	((1 << 20) - 1)
#define TEE_MMU_SECTION_TEX_SHIFT	12

#define TEE_MMU_SECTION_NS	(1 << 19)
#define TEE_MMU_SECTION_NG	(1 << 17)
#define TEE_MMU_SECTION_S	(1 << 16)
#define TEE_MMU_SECTION_AP2	(1 << 15)
#define TEE_MMU_SECTION_TEX(x)	(x << TEE_MMU_SECTION_TEX_SHIFT)
#define TEE_MMU_SECTION_AP1	(1 << 11)
#define TEE_MMU_SECTION_AP0	(1 << 10)
#define TEE_MMU_SECTION_DOMAIN(x) (x << 5)
#define TEE_MMU_SECTION_XN	(1 << 4)
#define TEE_MMU_SECTION_C	(1 << 3)
#define TEE_MMU_SECTION_B	(1 << 2)
#define TEE_MMU_SECTION		(2 << 0)

#define TEE_MMU_SECTION_AP(e) \
	((((e) >> 13) & 4) | (((e) >> 10) & 3))

#define TEE_MMU_SECTION_GET_TEX(e) \
	(((e) & TEE_MMU_SECTION_TEX(7)) >> TEE_MMU_SECTION_TEX_SHIFT)

/* User data, no cache attributes */
#define TEE_MMU_SECTION_UDATA \
	(TEE_MMU_SECTION_NG | TEE_MMU_SECTION_S | \
	TEE_MMU_SECTION_AP1 | TEE_MMU_SECTION_AP0 | TEE_MMU_SECTION_XN | \
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* User code, no cache attributes */
#define TEE_MMU_SECTION_UCODE \
	(TEE_MMU_SECTION_NG | TEE_MMU_SECTION_S | \
	TEE_MMU_SECTION_AP1 | TEE_MMU_SECTION_AP0 | \
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* Kernel data, global, privonly access, no exec, no cache attributes */
#define TEE_MMU_SECTION_KDATA \
	(TEE_MMU_SECTION_S | \
	TEE_MMU_SECTION_AP0 | TEE_MMU_SECTION_XN | \
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* Kernel data, global, privonly access, no exec, no cache attributes */
#define TEE_MMU_SECTION_KCODE \
	(TEE_MMU_SECTION_S | \
	TEE_MMU_SECTION_AP0 | \
	TEE_MMU_SECTION_DOMAIN(1) | TEE_MMU_SECTION)

/* Outer & Inner Write-Back, Write-Allocate. Default cache settings */
#define TEE_MMU_SECTION_CACHEMASK \
		(TEE_MMU_SECTION_TEX(7) | TEE_MMU_SECTION_C | TEE_MMU_SECTION_B)
#define TEE_MMU_SECTION_OIWBWA \
		(TEE_MMU_SECTION_TEX(1) | TEE_MMU_SECTION_C | TEE_MMU_SECTION_B)
#define TEE_MMU_SECTION_NOCACHE	\
		TEE_MMU_SECTION_TEX(1)

#define TEE_MMU_KL2_ENTRY(page_num) \
	    (*(uint32_t *)(SEC_VIRT_MMU_L2_BASE + ((uint32_t)(page_num)) * 4))

#define TEE_MMU_UL1_ENTRY(page_num) \
	    (*(uint32_t *)(TEE_MMU_UL1_BASE + ((uint32_t)(page_num)) * 4))

/* flags for L2 tables redirection */
#define TEE_MMU_COARSE_DOMAIN(x) (x << 5)
#define TEE_MMU_COARSE_NS	(1 << 3)
#define TEE_MMU_COARSE		(1 << 0)

#define TEE_MMU_COARSE_USER \
	(TEE_MMU_COARSE_DOMAIN(1) | TEE_MMU_COARSE)

/*
 * MMU small table page flags
 */
#define TEE_MMU_SPAGE_ATTR_MASK		((1 << 12) - 1)
#define TEE_MMU_SPAGE_TEX_SHIFT		6

#define TEE_MMU_SPAGE_NG	(1 << 11)
#define TEE_MMU_SPAGE_S		(1 << 10)
#define TEE_MMU_SPAGE_AP2	(1 << 9)
#define TEE_MMU_SPAGE_TEX(x)	(x << TEE_MMU_SPAGE_TEX_SHIFT)
#define TEE_MMU_SPAGE_AP1	(1 << 5)
#define TEE_MMU_SPAGE_AP0	(1 << 4)
#define TEE_MMU_SPAGE_C		(1 << 3)
#define TEE_MMU_SPAGE_B		(1 << 2)
#define TEE_MMU_SPAGE_XN	(1 << 0)
#define TEE_MMU_SPAGE		(2 << 0)

#define TEE_MMU_SPAGE_AP(e) \
	((((e) >> 7) & 4) | (((e) >> 4) & 3))

#define TEE_MMU_SPAGE_GET_TEX(e) \
	(((e) & TEE_MMU_SPAGE_TEX(7)) >> TEE_MMU_SPAGE_TEX_SHIFT)

#define TEE_MMU_SPAGE_UDATA \
	(TEE_MMU_SPAGE_NG | TEE_MMU_SPAGE_S | \
	TEE_MMU_SPAGE_AP1 | TEE_MMU_SPAGE_AP0 | TEE_MMU_SPAGE_XN | \
	TEE_MMU_SPAGE)

#define TEE_MMU_SPAGE_UCODE \
	(TEE_MMU_SPAGE_NG | TEE_MMU_SPAGE_S | \
	TEE_MMU_SPAGE_AP1 | TEE_MMU_SPAGE_AP0 | \
	TEE_MMU_SPAGE)

#define TEE_MMU_SPAGE_CACHEMASK \
	(TEE_MMU_SPAGE_TEX(7) | TEE_MMU_SPAGE_C | TEE_MMU_SPAGE_B)
#define TEE_MMU_SPAGE_OIWBWA \
	(TEE_MMU_SPAGE_TEX(1) | TEE_MMU_SPAGE_C | TEE_MMU_SPAGE_B)
#define TEE_MMU_SPAGE_NOCACHE \
	TEE_MMU_SPAGE_TEX(1)

/*
 * MMU large table page flags
 */
#define TEE_MMU_LPAGE_ATTR_MASK		((1 << 16) - 1)
#define TEE_MMU_LPAGE_TEX_SHIFT		12

#define TEE_MMU_LPAGE_XN	(1 << 15)
#define TEE_MMU_LPAGE_TEX(x)	(x << TEE_MMU_LPAGE_TEX_SHIFT)
#define TEE_MMU_LPAGE_NG	(1 << 10)
#define TEE_MMU_LPAGE_S		(1 << 10)
#define TEE_MMU_LPAGE_AP2	(1 << 9)
#define TEE_MMU_LPAGE_AP1	(1 << 5)
#define TEE_MMU_LPAGE_AP0	(1 << 4)
#define TEE_MMU_LPAGE_C		(1 << 3)
#define TEE_MMU_LPAGE_B		(1 << 2)
#define TEE_MMU_LPAGE		(1 << 0)

#define TEE_MMU_LPAGE_AP(e) \
	((((e) >> 7) & 4) | (((e) >> 4) & 3))

#define TEE_MMU_LPAGE_GET_TEX(e) \
	(((e) & TEE_MMU_LPAGE_TEX(7)) >> TEE_MMU_LPAGE_TEX_SHIFT)

#define TEE_MMU_LPAGE_UDATA \
	(TEE_MMU_LPAGE_NG | TEE_MMU_LPAGE_S | \
	TEE_MMU_LPAGE_AP1 | TEE_MMU_LPAGE_AP0 | TEE_MMU_LPAGE_XN | \
	TEE_MMU_LPAGE)

#define TEE_MMU_LPAGE_UCODE \
	(TEE_MMU_LPAGE_NG | TEE_MMU_LPAGE_S | \
	TEE_MMU_LPAGE_AP1 | TEE_MMU_LPAGE_AP0 | \
	TEE_MMU_LPAGE)

#define TEE_MMU_LPAGE_CACHEMASK \
	(TEE_MMU_LPAGE_TEX(7) | TEE_MMU_LPAGE_C | TEE_MMU_LPAGE_B)
#define TEE_MMU_LPAGE_OIWBWA \
	(TEE_MMU_LPAGE_TEX(1) | TEE_MMU_LPAGE_C | TEE_MMU_LPAGE_B)
#define TEE_MMU_LPAGE_NOCACHE \
	TEE_MMU_LPAGE_TEX(1)

/*
 * Generic marcos
 */
#define TEE_MMU_AP_USER_RO  0x02
#define TEE_MMU_AP_USER_RW  0x03

#endif
