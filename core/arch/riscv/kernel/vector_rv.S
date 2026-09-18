/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <riscv.h>
#include <riscv_macros.S>

/*
 * size_t vector_regs_size(void)
 *
 * Returns the header plus VECTOR_NUM_REGS * vlenb. vlenb is only readable
 * with the vector unit enabled, so it is enabled for the read and xstatus is
 * put back untouched, as in the two routines below.
 */
FUNC vector_regs_size , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	csrr	a0, CSR_VLENB

	csrw	CSR_XSTATUS, t1

	li	t0, VECTOR_REGS_NREGS
	mul	a0, a0, t0
	addi	a0, a0, VECTOR_REGS_VREGS_OFF
	ret
END_FUNC vector_regs_size

/*
 * void vector_save_regs(struct vector_regs *regs)
 *
 * Saves v0..v31 and the vector CSRs. The vector unit must be enabled by the
 * caller and xstatus is written back unmodified before returning.
 */
FUNC vector_save_regs , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	/* Take the CSRs before vstart is cleared below */
	csrr	t2, CSR_VSTART
	STR	t2, VECTOR_REGS_VSTART_OFF(a0)
	csrr	t2, CSR_VTYPE
	STR	t2, VECTOR_REGS_VTYPE_OFF(a0)
	csrr	t2, CSR_VL
	STR	t2, VECTOR_REGS_VL_OFF(a0)
	csrr	t2, CSR_VCSR
	STR	t2, VECTOR_REGS_VCSR_OFF(a0)

	/*
	 * The whole-register stores below honour vstart and would skip the
	 * elements below it, so start them from zero.
	 */
	csrw	CSR_VSTART, zero

	csrr	t2, CSR_VLENB
	addi	a1, a0, VECTOR_REGS_VREGS_OFF
	store_vregs a1, t2, t3

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC vector_save_regs

/*
 * void vector_restore_regs(struct vector_regs *regs)
 *
 * Loads v0..v31 and the vector CSRs. Enables and restores xstatus as above.
 */
FUNC vector_restore_regs , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	/* As above, the whole-register loads must start from vstart zero */
	csrw	CSR_VSTART, zero

	csrr	t2, CSR_VLENB
	addi	a1, a0, VECTOR_REGS_VREGS_OFF
	load_vregs a1, t2, t3

	/*
	 * vl and vtype are read only, the pair is put back by re-running the
	 * vsetvl that produced them.
	 */
	LDR	t2, VECTOR_REGS_VL_OFF(a0)
	LDR	t3, VECTOR_REGS_VTYPE_OFF(a0)
	.option push
	.option arch, +v
	vsetvl	zero, t2, t3
	.option pop

	LDR	t2, VECTOR_REGS_VSTART_OFF(a0)
	csrw	CSR_VSTART, t2
	LDR	t2, VECTOR_REGS_VCSR_OFF(a0)
	csrw	CSR_VCSR, t2

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC vector_restore_regs
