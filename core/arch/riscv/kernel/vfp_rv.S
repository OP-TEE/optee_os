/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <riscv.h>
#include <riscv_macros.S>

/* void vfp_save_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_save_extension_regs , :
	store_fregs a0, 0, 0, 31
	ret
END_FUNC vfp_save_extension_regs

/* void vfp_restore_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_restore_extension_regs , :
	load_fregs a0, 0, 0, 31
	ret
END_FUNC vfp_restore_extension_regs

/*
 * void vfp_clear_extension_regs(void);
 *
 * Reset the FP context to a clean state: zero f0..f31 and fcsr. The FP
 * unit must be enabled by the caller.
 */
FUNC vfp_clear_extension_regs , :
	csrw	fcsr, zero
	clear_fregs 0, 31
	ret
END_FUNC vfp_clear_extension_regs

#if defined(CFG_RISCV_ISA_V)

/* Advance base_reg by 8 vector registers (8 * vlenb). t3 clobbered. */
.macro __vreg_advance base_reg, vlenb_reg
	slli	t3, \vlenb_reg, 3
	add	\base_reg, \base_reg, t3
.endm

/*
 * Move the whole vector register file with the whole-register form \op
 * (vs8r.v or vl8r.v), eight registers at a time. base_reg is left past the
 * end. The vector ISA is enabled for this block alone.
 */
.macro do_all_vreg_chunks op, base_reg, vlenb_reg
	.option push
	.option arch, +v
	\op	v0, (\base_reg)
	__vreg_advance \base_reg, \vlenb_reg
	\op	v8, (\base_reg)
	__vreg_advance \base_reg, \vlenb_reg
	\op	v16, (\base_reg)
	__vreg_advance \base_reg, \vlenb_reg
	\op	v24, (\base_reg)
	.option pop
.endm

/*
 * size_t riscv_vector_state_size(void)
 *
 * Returns the offset of the registers in struct riscv_vector_state plus
 * 32 * vlenb. vlenb is only readable with the vector unit enabled, so it is
 * enabled for the read and xstatus is put back untouched.
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
	addi	a0, a0, RISCV_VECTOR_STATE_VREGS
	ret
END_FUNC riscv_vector_state_size

/*
 * void vfp_save_vector_regs(struct riscv_vector_state *state)
 *
 * The caller has enabled the vector unit and passes a non-NULL state.
 */
FUNC vfp_save_vector_regs , :
	csrr	t0, CSR_VCSR
	STR	t0, RISCV_VECTOR_STATE_VCSR(a0)
	csrr	t0, CSR_VSTART
	STR	t0, RISCV_VECTOR_STATE_VSTART(a0)
	csrr	t0, CSR_VL
	STR	t0, RISCV_VECTOR_STATE_VL(a0)
	csrr	t0, CSR_VTYPE
	STR	t0, RISCV_VECTOR_STATE_VTYPE(a0)

	/*
	 * vstart is saved above; zero it so the whole-register stores start
	 * from element 0 (vs8r.v honours vstart and would otherwise skip the
	 * first vstart elements of a context interrupted mid-vector-op).
	 */
	csrw	CSR_VSTART, zero

	csrr	t2, CSR_VLENB
	addi	a1, a0, RISCV_VECTOR_STATE_VREGS
	do_all_vreg_chunks vs8r.v, a1, t2

	ret
END_FUNC vfp_save_vector_regs

/*
 * void vfp_restore_vector_regs(const struct riscv_vector_state *state)
 *
 * The caller has enabled the vector unit and passes a non-NULL state.
 */
FUNC vfp_restore_vector_regs , :
	/*
	 * Zero vstart so the whole-register loads start from element 0
	 * (vl8r.v honours vstart); the saved vstart is reinstated below.
	 */
	csrw	CSR_VSTART, zero

	csrr	t2, CSR_VLENB
	addi	a1, a0, RISCV_VECTOR_STATE_VREGS
	do_all_vreg_chunks vl8r.v, a1, t2

	LDR	t0, RISCV_VECTOR_STATE_VCSR(a0)
	csrw	CSR_VCSR, t0

	/*
	 * vl and vtype are read-only CSRs; reinstate them with vsetvl using
	 * the saved vl as the requested AVL and the saved vtype. vsetvl also
	 * clears vstart, so restore vstart afterwards.
	 */
	LDR	t0, RISCV_VECTOR_STATE_VL(a0)
	LDR	t3, RISCV_VECTOR_STATE_VTYPE(a0)
	.option push
	.option arch, +v
	vsetvl	x0, t0, t3
	.option pop

	LDR	t0, RISCV_VECTOR_STATE_VSTART(a0)
	csrw	CSR_VSTART, t0

	ret
END_FUNC vfp_restore_vector_regs

/*
 * void vfp_clear_vector_regs(void);
 *
 * Zero v0-v31 and vcsr in place. The caller has enabled the vector unit.
 */
FUNC vfp_clear_vector_regs , :
	.option push
	.option arch, +v
	csrw	CSR_VSTART, zero
	vsetvli	t0, zero, e8, m8, ta, ma
	vmv.v.i	v0, 0
	vmv.v.i	v8, 0
	vmv.v.i	v16, 0
	vmv.v.i	v24, 0
	csrw	CSR_VCSR, zero
	.option pop
	ret
END_FUNC vfp_clear_vector_regs

#endif /* CFG_RISCV_ISA_V */
