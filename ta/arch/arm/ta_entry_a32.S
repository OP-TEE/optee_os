/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <asm.S>

/*
 * This function is the bottom of the user call stack. Mark it as such so that
 * the unwinding code won't try to go further down.
 * We need an assembly wrapper because Clang does not accept asm(".cantunwind")
 * in a C function:
 *
 *  user_ta_header.c:44:6: error: .fnstart must precede .cantunwind directive
 *          asm(".cantunwind");
 *              ^
 */
FUNC __ta_entry, :
UNWIND(	.cantunwind)
	bl	__ta_entry_c
END_FUNC __ta_entry
