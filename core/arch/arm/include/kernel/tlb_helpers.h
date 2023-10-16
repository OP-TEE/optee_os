/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __KERNEL_TLB_HELPERS_H
#define __KERNEL_TLB_HELPERS_H

#include <arm.h>

#ifndef __ASSEMBLER__
#include <types_ext.h>

void tlbi_all(void);
void tlbi_asid(unsigned long asid);
void tlbi_va_allasid(unsigned long addr);

static inline void tlbi_va_allasid_nosync(vaddr_t va)
{
#ifdef ARM64
	tlbi_vaae1is(va >> TLBI_VA_SHIFT);
#else
	write_tlbimvaais(va);
#endif
}

static inline void tlbi_va_asid_nosync(vaddr_t va, uint32_t asid)
{
	uint32_t a = asid & TLBI_ASID_MASK;

#ifdef ARM64
	tlbi_vale1is((va >> TLBI_VA_SHIFT) | SHIFT_U64(a, TLBI_ASID_SHIFT));
	tlbi_vale1is((va >> TLBI_VA_SHIFT) |
		     SHIFT_U64(a | 1, TLBI_ASID_SHIFT));
#else
	write_tlbimvais((va & ~(BIT32(TLBI_MVA_SHIFT) - 1)) | a);
	write_tlbimvais((va & ~(BIT32(TLBI_MVA_SHIFT) - 1)) | a | 1);
#endif
}

static inline void tlbi_va_asid(vaddr_t va, uint32_t asid)
{
	dsb_ishst();
	tlbi_va_asid_nosync(va, asid);
	dsb_ish();
	isb();
}
#endif /*!__ASSEMBLER__*/

#endif /* __KERNEL_TLB_HELPERS_H */
