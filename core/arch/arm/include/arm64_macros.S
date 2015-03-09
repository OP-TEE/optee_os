/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

