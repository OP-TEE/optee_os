/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023,2026 NXP
 * Copyright (c) 2015, Linaro Limited
 */

	.altmacro


	/*
	 * This helper macro emits a single load/store of one register,
	 * \reg_prefix\reg (x5, f5, ...), at \base_offs(\base_reg).
	 */
	.macro __do_reg instr, reg_prefix, base_reg, base_offs, reg
		\instr \reg_prefix\reg, \base_offs(\base_reg)
	.endm

	/*
	 * This helper macro emits one load/store per register in
	 * \reg_prefix[\from_regnum]..\reg_prefix[\to_regnum], mapped at
	 * \base_offs(\base_reg) with \reg_bytes per register. Registers are
	 * emitted from \to_regnum down to \from_regnum. A single register is
	 * emitted when \to_regnum is omitted.
	 */
	.macro _do_regs instr, reg_prefix, reg_bytes, base_reg, base_offs, \
			from_regnum, to_regnum
		.set .L_do_regs_to, \from_regnum
		.ifnb \to_regnum
			.set .L_do_regs_to, \to_regnum
		.endif
		.set .L_do_regs_num, .L_do_regs_to
		.set .L_do_regs_offs, \
			\base_offs + (.L_do_regs_to - \from_regnum) * \reg_bytes
		.rept (.L_do_regs_to - \from_regnum + 1)
			__do_reg \instr, \reg_prefix, \base_reg, \
				 %.L_do_regs_offs, %.L_do_regs_num
			.set .L_do_regs_num, .L_do_regs_num - 1
			.set .L_do_regs_offs, .L_do_regs_offs - \reg_bytes
		.endr
	.endm

	/*
	 * Stores registers x[from_regnum]..x[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro store_xregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs STR, x, RISCV_XLEN_BYTES, \base_reg, \base_offs, \
			 \from_regnum, \to_regnum
	.endm

	/*
	 * Loads registers x[from_regnum]..x[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro load_xregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs LDR, x, RISCV_XLEN_BYTES, \base_reg, \base_offs, \
			 \from_regnum, \to_regnum
	.endm

	/*
	 * Multiplication macro for RISC-V harts without M extension.
	 */
	.macro mult, reg_op0, reg_op1, reg_res
		li	\reg_res, 0
		mv	a0, \reg_op0
		mv	a1, \reg_op1
		mv	a2, a0
		li	a0, 0
	1:
		andi	a3, a1, 1
		beqz	a3, 2f
		add	a0, a0, a2
	2:
		srli	a1, a1, 1
		slli	a2, a2, 1
		bnez	a1, 1b
		add	\reg_res, \reg_res, a0
	.endm

	.macro panic_at_abi_return
#if defined(CFG_TEE_CORE_DEBUG)
		jal	__panic_at_abi_return
#else
		j	.
#endif
	.endm

	/*
	 * Write \reg to xstatus, keeping the live VS field. The vector unit is
	 * enabled and disabled through vfp_enable()/vfp_disable() only, so VS is
	 * not part of the saved context and must survive a context restore.
	 */
	.macro write_xstatus_keep_vs reg, tmp
#if defined(CFG_WITH_VFP) && defined(CFG_RISCV_VEC)
		csrr	\tmp, CSR_XSTATUS
		xor	\tmp, \tmp, \reg
		srli	\tmp, \tmp, CSR_XSTATUS_VS_SHIFT
		andi	\tmp, \tmp, CSR_XSTATUS_VS_MASK >> CSR_XSTATUS_VS_SHIFT
		slli	\tmp, \tmp, CSR_XSTATUS_VS_SHIFT
		xor	\reg, \reg, \tmp
#endif
		csrw	CSR_XSTATUS, \reg
	.endm

	/* Advance base_reg by 8 vector registers (8 * vlenb). t3 clobbered. */
	.macro __vreg_advance base_reg, vlenb_reg
		slli	t3, \vlenb_reg, 3
		add	\base_reg, \base_reg, t3
	.endm

	/*
	 * Move the whole vector register file with the whole-register form
	 * \op (vs8r.v or vl8r.v), eight registers at a time. base_reg is left
	 * past the end. The vector ISA is enabled for this block alone.
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
