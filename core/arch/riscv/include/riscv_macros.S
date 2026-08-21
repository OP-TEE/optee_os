/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 * Copyright (c) 2015, Linaro Limited
 */

	.altmacro


	/*
	 * This helper macro concatenates instr_prefix, instr_suffix, to
	 * create a l(w,d)/s(w,d) instruction.
	 */
	.macro __do_reg instr_prefix, base_reg, base_offs, reg
		\instr_prefix x\reg, \base_offs(\base_reg)
	.endm

	/*
	 * This helper macro uses recursion to create a loop with a single
	 * load/store.
	 */
	.macro _do_regs instr_prefix, reg_bytes, base_reg, base_offs, \
			from_regnum, to_regnum

		.if (\to_regnum - \from_regnum + 1) > 1
			_do_regs \instr_prefix, \reg_bytes, \base_reg, \
				%(\base_offs + 1 * \reg_bytes), \
				%(\from_regnum + 1), \to_regnum
		.endif

		__do_reg \instr_prefix, \base_reg, \base_offs, \from_regnum
	.endm

	/*
	 * Stores registers x[from_regnum]..x[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro store_xregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs STR, RISCV_XLEN_BYTES, \base_reg, \base_offs, \
			 \from_regnum, \to_regnum
	.endm

	/*
	 * Loads registers x[from_regnum]..x[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro load_xregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs LDR, RISCV_XLEN_BYTES, \base_reg, \base_offs, \
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
	 * Advance base pointer to next group of eight vector registers.
	 *
	 * One whole-register instruction (vs8r.v/vl8r.v) stores or restores
	 * eight vector registers, so advance by 8 * VLENB bytes.
	 */
	.macro __vreg_advance base_reg, vlenb_reg
		slli	t3, \vlenb_reg, 3         /* t3 = vlenb * 8 */
		add	\base_reg, \base_reg, t3  /* Advance pointer by 8 vector registers */
	.endm

	/* Helper macro to save/restore all 32 vector registers in chunks of 8 */
	.macro do_all_vreg_chunks op, base_reg, vlenb_reg
		.option push
		.option arch, +v, +zicsr, +m

		\op	v0, (\base_reg)
		__vreg_advance \base_reg, \vlenb_reg
		\op	v8, (\base_reg)
		__vreg_advance \base_reg, \vlenb_reg
		\op	v16, (\base_reg)
		__vreg_advance \base_reg, \vlenb_reg
		\op	v24, (\base_reg)

		.option pop
	.endm

