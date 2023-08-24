/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

	.altmacro

	/*
	 * This helper macro concatenates instr_prefix, instr_suffix, to
	 * create a ldp/stp instruction. It also selects register name x/w
	 * based on reg_bytes.
	 */
	.macro __do_dregs instr_prefix, instr_suffix, reg_bytes, base_reg, \
			base_offs, reg0, reg1
		.if \reg_bytes == 8
			\instr_prefix\instr_suffix \
				x\reg0, x\reg1, [\base_reg, #\base_offs]
		.else
			\instr_prefix\instr_suffix \
				w\reg0, w\reg1, [\base_reg, #\base_offs]
		.endif
	.endm

	/*
	 * This helper macro concatenates instr_prefix, instr_suffix, to
	 * create a ldr/str instruction. It also selects register name x/w
	 * based on reg_bytes.
	 */
	.macro __do_reg instr_prefix, instr_suffix, reg_bytes, base_reg, \
			base_offs, reg
		.if \reg_bytes == 8
			\instr_prefix\instr_suffix \
				x\reg, [\base_reg, #\base_offs]
		.else
			\instr_prefix\instr_suffix \
				w\reg, [\base_reg, #\base_offs]
		.endif
	.endm

	/*
	 * This helper macro uses recursion to create a loop which will
	 * start with generating instructions for register pairs and if
	 * it's an odd number of registers end with a single load/store.
	 */
	.macro _do_regs instr_prefix, reg_bytes, base_reg, base_offs, \
			from_regnum, to_regnum
		.if (\to_regnum - \from_regnum + 1) >= 2
			__do_dregs \instr_prefix, p, \reg_bytes, \base_reg, \
				\base_offs, \from_regnum, %(\from_regnum + 1)
		.else
			__do_reg \instr_prefix, r, \reg_bytes, \base_reg, \
				\base_offs, \from_regnum
		.endif
		.if (\to_regnum - \from_regnum + 1) > 2
			_do_regs \instr_prefix, \reg_bytes, \base_reg, \
				%(\base_offs + 2 * \reg_bytes), \
				%(\from_regnum + 2), \to_regnum
		.endif
	.endm

	/*
	 * Stores registers x[from_regnum]..x[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro store_xregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs st 8 \base_reg, \base_offs, \from_regnum, \to_regnum
	.endm

	/*
	 * Stores registers w[from_regnum]..w[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro store_wregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs st 4 \base_reg, \base_offs, \from_regnum, \to_regnum
	.endm

	/*
	 * Loads registers x[from_regnum]..x[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro load_xregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs ld 8 \base_reg, \base_offs, \from_regnum, \to_regnum
	.endm

	/*
	 * Loads registers w[from_regnum]..w[to_regnum] at
	 * [base_reg, #base_offs]
	 */
	.macro load_wregs base_reg, base_offs, from_regnum, to_regnum
		_do_regs ld 4 \base_reg, \base_offs, \from_regnum, \to_regnum
	.endm


	/* Push register pair on stack */
	.macro  push, r1, r2
	stp     \r1, \r2, [sp, #-16]!
	.endm

	/* Pop register pair from stack */
	.macro  pop, r1, r2
	ldp     \r1, \r2, [sp], #16
	.endm

	.macro mov_imm _reg, _val
	.if (((\_val) >> 31) == 0 || ((\_val) >> 31) == 0x1ffffffff)
		movz    \_reg, :abs_g1_s:\_val
	.else
		.if (((\_val) >> 47) == 0 || ((\_val) >> 47) == 0x1ffff)
			movz    \_reg, :abs_g2_s:\_val
		.else
			movz    \_reg, :abs_g3:\_val
			movk    \_reg, :abs_g2_nc:\_val
		.endif
		movk    \_reg, :abs_g1_nc:\_val
	.endif
		movk    \_reg, :abs_g0_nc:\_val
	.endm

	.macro add_imm _reg, _val
	.if ((\_val) > 0xfff)
		add	\_reg, \_reg, ((\_val) >> 12), LSL #12
	.endif
	.if (((\_val) & 0xfff) > 0)
		add	\_reg, \_reg, ((\_val) & 0xfff)
	.endif
	.endm

	.macro sub_imm _reg, _val
	.if ((\_val) > 0xfff)
		sub	\_reg, \_reg, ((\_val) >> 12), LSL #12
	.endif
	.if (((\_val) & 0xfff) > 0)
		sub	\_reg, \_reg, ((\_val) & 0xfff)
	.endif
	.endm

	/*
	 * Load address of <sym> into <reg>, <sym> being in the range
	 * +/- 4GB of the PC (note that 'adr reg, sym' is limited to +/- 1MB).
	 */
	.macro adr_l reg, sym
	adrp	\reg, \sym
	add	\reg, \reg, :lo12:\sym
	.endm

	.macro panic_at_smc_return
#if defined(CFG_TEE_CORE_DEBUG)
		bl	__panic_at_smc_return
#else
		b	.
#endif
	.endm

	.macro read_apiakeylo reg
	mrs	\reg, S3_0_c2_c1_0
	.endm

	.macro read_apiakeyhi reg
	mrs	\reg, S3_0_c2_c1_1
	.endm

	.macro write_apiakeylo reg
	msr	S3_0_c2_c1_0, \reg
	.endm

	.macro write_apiakeyhi reg
	msr	S3_0_c2_c1_1, \reg
	.endm

	.macro write_pan reg
	/* msr pan, \reg */
	msr	S3_0_c4_c2_3, \reg
	.endm

	.macro write_pan_enable
	/* msr pan, #1 */
	msr	S0_0_c4_c1_4, xzr
	.endm

	.macro write_pan_disable
	/* msr pan, #0 */
	msr	S0_0_c4_c0_4, xzr
	.endm
