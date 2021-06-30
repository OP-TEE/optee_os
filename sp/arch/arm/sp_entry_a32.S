/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2021, Arm Limited.
 */

#include <asm.S>

/*
 * This function is the bottom of the user call stack. Mark it as such so that
 * the unwinding code won't try to go further down.
 * Please reference ta_entry_a32.S for more information.
 */
FUNC __sp_entry, :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	bl	__sp_entry_c
UNWIND(	.fnend)
END_FUNC __sp_entry
