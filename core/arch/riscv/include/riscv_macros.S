/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 * Copyright (c) 2015, Linaro Limited
 * Copyright 2026, RISCStar Solutions Limited
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
	 * Base macro to emit a single floating-point load/store instruction.
	 */
	.macro __do_fpreg instr, base_reg, base_offs, regnum
		\instr f\regnum, \base_offs(\base_reg)
	.endm

	.macro __do_fpreg_expanded instr, base_reg, base_offs, regnum
		__do_fpreg \instr, \base_reg, \base_offs, \regnum
	.endm

	/*
	 * Recursive helper macro to loop through a range of floating-point
	 * registers.
	 */
	.macro _do_fpregs instr, base_reg, base_offs, from_regnum, to_regnum
		.if \from_regnum < \to_regnum
			_do_fpregs \instr, \base_reg, \
				   %(\base_offs + FP_REG_BYTES), \
				   %(\from_regnum + 1), \to_regnum
		.endif

		__do_fpreg_expanded \instr, \base_reg, \base_offs, \from_regnum
	.endm

	/*
	 * Stores floating-point registers f[from_regnum] .. f[to_regnum].
	 *
	 * Instruction and stride are selected internally from RISCV_XLEN_BITS.
	 */
	.macro store_fpregs base_reg, base_offs, from_regnum, to_regnum
		_do_fpregs FST, \base_reg, \base_offs, \from_regnum, \to_regnum
	.endm

	/*
	 * Loads floating-point registers f[from_regnum] .. f[to_regnum].
	 *
	 * Instruction and stride are selected internally from RISCV_XLEN_BITS.
	 */
	.macro load_fpregs base_reg, base_offs, from_regnum, to_regnum
		_do_fpregs FLD, \base_reg, \base_offs, \from_regnum, \to_regnum
	.endm
