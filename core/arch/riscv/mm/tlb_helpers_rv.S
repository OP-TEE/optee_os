/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022,2026 NXP
 */

#include <asm.S>

/*
 * SFENCE.VMA only orders the calling hart. The helpers below are local
 * primitives; the hart-wide variants without the _local suffix are
 * implemented in core_mmu_arch.c on top of the SBI RFENCE extension.
 */

/* void tlbi_all_local(void); */
FUNC tlbi_all_local , :
	sfence.vma	zero, zero
	ret
END_FUNC tlbi_all_local

/* void tlbi_va_allasid_local(vaddr_t va); */
FUNC tlbi_va_allasid_local , :
	sfence.vma	a0, zero
	ret
END_FUNC tlbi_va_allasid_local

/* void tlbi_asid_local(unsigned long asid); */
FUNC tlbi_asid_local , :
	sfence.vma	zero, a0
	ret
END_FUNC tlbi_asid_local

/* void tlbi_va_asid_local(vaddr_t va, uint32_t asid); */
FUNC tlbi_va_asid_local , :
	sfence.vma	a0, a1
	ret
END_FUNC tlbi_va_asid_local
