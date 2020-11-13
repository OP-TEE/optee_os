/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2018, STMicroelectronics
 */

#include <arm32.h>
#include <arm32_macros.S>
#include <asm.S>

.section .text
.balign 4
.code 32

#define STM32MP1_NSACR_PRESERVE_MASK	(0xfff << 20)

FUNC plat_cpu_reset_early , :
	ldr	r0, =SCR_SIF
	write_scr r0

	read_nsacr r0
	mov_imm	r1, STM32MP1_NSACR_PRESERVE_MASK
	and	r0, r0, r1
	write_nsacr r0

	isb
	bx	lr
END_FUNC plat_cpu_reset_early
