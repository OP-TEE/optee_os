/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <riscv.h>
#include <riscv_macros.S>

#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)

/*
 * size_t riscv_vector_state_size(void)
 *
 * Returns sizeof(the four CSR words) + VECTOR_NUM_REGS * vlenb. vlenb is only
 * readable with the vector unit enabled, so it is enabled for the read and
 * xstatus is put back untouched.
 */
FUNC riscv_vector_state_size , :
	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrc	CSR_XSTATUS, t0
	li	t0, (CSR_XSTATUS_VS_INITIAL << CSR_XSTATUS_VS_SHIFT)
	csrs	CSR_XSTATUS, t0

	csrr	a0, CSR_VLENB

	csrw	CSR_XSTATUS, t1

	li	t0, 32
	mul	a0, a0, t0
	addi	a0, a0, (RISCV_XLEN_BYTES * 4)
	ret
END_FUNC riscv_vector_state_size

/*
 * void riscv_vector_save(struct riscv_vector_state *state)
 * Layout: 0 -> vcsr, XLEN -> vstart, XLEN*2 -> vl, XLEN*3 -> vtype,
 *	   XLEN*4 -> vregs
 */
FUNC riscv_vector_save , :
	beqz	a0, 1f

	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	csrr	t0, CSR_VCSR
	STR	t0, 0(a0)
	csrr	t0, CSR_VSTART
	STR	t0, RISCV_XLEN_BYTES(a0)
	csrr	t0, CSR_VL
	STR	t0, (RISCV_XLEN_BYTES * 2)(a0)
	csrr	t0, CSR_VTYPE
	STR	t0, (RISCV_XLEN_BYTES * 3)(a0)

	csrr	t2, CSR_VLENB
	addi	a1, a0, (RISCV_XLEN_BYTES * 4)
	do_all_vreg_chunks vs8r.v, a1, t2

	csrw	CSR_XSTATUS, t1
1:
	ret
END_FUNC riscv_vector_save

/*
 * void riscv_vector_restore(const struct riscv_vector_state *state)
 */
FUNC riscv_vector_restore , :
	beqz	a0, 1f

	csrr	t1, CSR_XSTATUS
	li	t0, CSR_XSTATUS_VS_MASK
	csrs	CSR_XSTATUS, t0

	csrr	t2, CSR_VLENB
	addi	a1, a0, (RISCV_XLEN_BYTES * 4)
	do_all_vreg_chunks vl8r.v, a1, t2

	LDR	t0, 0(a0)
	csrw	CSR_VCSR, t0

	/*
	 * vl and vtype are read-only CSRs; reinstate them with vsetvl using
	 * the saved vl as the requested AVL and the saved vtype. vsetvl also
	 * clears vstart, so restore vstart afterwards.
	 */
	LDR	t0, (RISCV_XLEN_BYTES * 2)(a0)
	LDR	t3, (RISCV_XLEN_BYTES * 3)(a0)
	.option push
	.option arch, +v
	vsetvl	x0, t0, t3
	.option pop

	LDR	t0, RISCV_XLEN_BYTES(a0)
	csrw	CSR_VSTART, t0

	csrw	CSR_XSTATUS, t1
1:
	ret
END_FUNC riscv_vector_restore

#endif /* CFG_WITH_VFP && CFG_RISCV_VEC */
