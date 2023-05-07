/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#include <asm.S>
#include <riscv.h>
#include <util.h>

/* void tlbi_all(void); */
FUNC tlbi_all , :
	sfence.vma	zero, zero
END_FUNC tlbi_all

/* void tlbi_mva_allasid(vaddr_t mva); */
FUNC tlbi_mva_allasid , :
	sfence.vma	a0, zero
END_FUNC tlbi_mva_allasid

/* void tlbi_asid(unsigned int asid); */
FUNC tlbi_asid , :
	sfence.vma	zero, a0
END_FUNC tlbi_asid
