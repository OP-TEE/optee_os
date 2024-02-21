/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <asm.S>

/*
 * uintptr_t __do_semihosting(uintptr_t op, uintptr_t arg)
 *
 * Refer to RISC-V Semihosting Binary Interface:
 * https://github.com/riscv-non-isa/riscv-semihosting/blob/main/binary-interface.adoc
 */
FUNC __do_semihosting , : , .identity_map
.option push
.option norvc
	slli	x0, x0, 0x1f
	ebreak
	srai    x0, x0, 0x7
.option pop
	ret
END_FUNC __do_semihosting
