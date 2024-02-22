/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Linaro, Ltd.
 */

#include <asm.S>

/*
 * uintptr_t __do_semihosting(uintptr_t op, uintptr_t arg)
 *
 * Refer to "Semihosting for Aarch32 and Aarch64":
 * https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst
 */
FUNC __do_semihosting , :
	hlt	#0xf000
	ret
END_FUNC __do_semihosting
