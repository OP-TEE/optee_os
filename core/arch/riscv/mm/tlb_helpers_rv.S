/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022 NXP
 */

#include <asm.S>

/* void tlbi_all(void); */
FUNC tlbi_all , :
	sfence.vma	zero, zero
	ret
END_FUNC tlbi_all

/* void tlbi_va_allasid(vaddr_t va); */
FUNC tlbi_va_allasid , :
	sfence.vma	a0, zero
	ret
END_FUNC tlbi_va_allasid

/* void tlbi_asid(unsigned int asid); */
FUNC tlbi_asid , :
	sfence.vma	zero, a0
	ret
END_FUNC tlbi_asid

/* void tlbi_va_asid(vaddr_t va, uint32_t asid); */
FUNC tlbi_va_asid , :
	sfence.vma	a0, a1
	ret
END_FUNC tlbi_va_asid
