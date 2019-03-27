/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <asm.S>

#if defined(CFG_UNWIND)
#define UNWIND(...)     __VA_ARGS__
#else
#define UNWIND(...)
#endif

	FUNC __utee_entry, :
UNWIND( .fnstart)
UNWIND(	.cantunwind)
	bl	__utee_entry_c
	/* Not reached */
	/*
	 * The nop makes the output of symbolize.py nicer. Stack dump shows LR
	 * which would be outside of the function without this.
	 */
	nop
UNWIND( .fnend)
	END_FUNC __utee_entry
