/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023,2026 NXP
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2026, RISCStar Solutions Limited
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
	 * Save f registers from_regnum..to_regnum to memory at
	 * [base_reg, #base_offs], RISCV_FLEN_BYTES apart
	 */
	.macro store_fregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs FSTR, f, RISCV_FLEN_BYTES, \base_reg, \base_offs, \
			 \from_regnum, \to_regnum
	.endm

	/*
	 * Load f registers from_regnum..to_regnum from memory at
	 * [base_reg, #base_offs], RISCV_FLEN_BYTES apart
	 */
	.macro load_fregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs FLDR, f, RISCV_FLEN_BYTES, \base_reg, \base_offs, \
			 \from_regnum, \to_regnum
	.endm

	/*
	 * This helper macro zeroes one f register, f\reg.
	 */
	.macro __clear_freg reg
#if RISCV_FLEN_BITS == 32
		fmv.w.x	f\reg, zero
#else
		fmv.d.x	f\reg, zero
#endif
	.endm

	/*
	 * Zero f registers from_regnum..to_regnum.
	 */
	.macro clear_fregs from_regnum, to_regnum
		.set .L_clear_fregs_num, \from_regnum
		.rept (\to_regnum - \from_regnum + 1)
			__clear_freg %.L_clear_fregs_num
			.set .L_clear_fregs_num, .L_clear_fregs_num + 1
		.endr
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
