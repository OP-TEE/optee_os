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

#ifdef CFG_RISCV_ISA_SVINVAL
.option push
.option arch, +svinval
/*
 * Svinval splits SFENCE.VMA into SINVAL.VMA, which only invalidates, and
 * two fences: SFENCE.W.INVAL orders the page table stores before the
 * invalidations, SFENCE.INVAL.IR orders the invalidations before later
 * implicit page table reads. A range is invalidated with one fence pair
 * around a run of SINVAL.VMA instead of a full SFENCE.VMA per page.
 *
 * void tlbi_va_range_local(vaddr_t va, size_t len, size_t granule);
 */
FUNC tlbi_va_range_local , :
	add	a1, a0, a1
	sfence.w.inval
1:	sinval.vma	a0, zero
	add	a0, a0, a2
	bltu	a0, a1, 1b
	sfence.inval.ir
	ret
END_FUNC tlbi_va_range_local

/*
 * void tlbi_va_range_asid_local(vaddr_t va, size_t len, size_t granule,
 *				 uint32_t asid);
 */
FUNC tlbi_va_range_asid_local , :
	add	a1, a0, a1
	sfence.w.inval
1:	sinval.vma	a0, a3
	add	a0, a0, a2
	bltu	a0, a1, 1b
	sfence.inval.ir
	ret
END_FUNC tlbi_va_range_asid_local
.option pop
#endif /*CFG_RISCV_ISA_SVINVAL*/
