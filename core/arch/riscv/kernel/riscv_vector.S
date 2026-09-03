/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <riscv.h>
#include <riscv_macros.S>

/*
 * size_t riscv_vector_state_size(void)
 *
 * Returns the header plus 32 * vlenb. vlenb is only readable with the
 * vector unit enabled, so it is enabled for the read and xstatus is put
 * back untouched, as in the two routines below.
 */
FUNC riscv_vector_state_size , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	csrr	a0, CSR_VLENB

	csrw	CSR_XSTATUS, t1

	li	t0, RISCV_VECTOR_NREGS
	mul	a0, a0, t0
	addi	a0, a0, RISCV_VECTOR_VREGS_OFF
	ret
END_FUNC riscv_vector_state_size

/*
 * void riscv_vector_save_state(struct riscv_vector_state *state)
 *
 * Saves v0..v31 and the vector CSRs. The vector unit is enabled for the
 * duration of the transfer and xstatus is written back unmodified before
 * returning, so the caller's VS state is preserved.
 */
FUNC riscv_vector_save_state , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	/* Take the CSRs before vstart is cleared below */
	csrr	t2, CSR_VSTART
	STR	t2, RISCV_VECTOR_VSTART_OFF(a0)
	csrr	t2, CSR_VTYPE
	STR	t2, RISCV_VECTOR_VTYPE_OFF(a0)
	csrr	t2, CSR_VL
	STR	t2, RISCV_VECTOR_VL_OFF(a0)
	csrr	t2, CSR_VCSR
	STR	t2, RISCV_VECTOR_VCSR_OFF(a0)

	/*
	 * The whole-register stores below honour vstart and would skip the
	 * elements below it, so start them from zero.
	 */
	csrw	CSR_VSTART, zero

	csrr	t2, CSR_VLENB
	addi	a1, a0, RISCV_VECTOR_VREGS_OFF
	store_vregs a1, t2, t3

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC riscv_vector_save_state

/*
 * void riscv_vector_restore_state(struct riscv_vector_state *state)
 *
 * Loads v0..v31 and the vector CSRs. Enables and restores xstatus as above.
 */
FUNC riscv_vector_restore_state , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	/* As above, the whole-register loads must start from vstart zero */
	csrw	CSR_VSTART, zero

	csrr	t2, CSR_VLENB
	addi	a1, a0, RISCV_VECTOR_VREGS_OFF
	load_vregs a1, t2, t3

	/*
	 * vl and vtype are read only, the pair is put back by re-running the
	 * vsetvl that produced them.
	 */
	LDR	t2, RISCV_VECTOR_VL_OFF(a0)
	LDR	t3, RISCV_VECTOR_VTYPE_OFF(a0)
	.option push
	.option arch, +v
	vsetvl	zero, t2, t3
	.option pop

	LDR	t2, RISCV_VECTOR_VSTART_OFF(a0)
	csrw	CSR_VSTART, t2
	LDR	t2, RISCV_VECTOR_VCSR_OFF(a0)
	csrw	CSR_VCSR, t2

	csrw	CSR_XSTATUS, t1
	ret
END_FUNC riscv_vector_restore_state
