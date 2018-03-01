/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, NXP
 *
 * Peng Fan  <peng.fan@nxp.com>
 */

/*
 * Entry points for the A7 init.
 * It is assume no stack is available when these routines are called.
 * It is assume each routine is called with return address in LR
 * and with ARM registers R0, R1, R2, R3 being scratchable.
 */

#include <arm.h>
#include <arm32.h>
#include <arm32_macros.S>
#include <asm.S>
#include <kernel/unwind.h>
#include <platform_config.h>

.section .text
.balign 4
.code 32

/*
 * Cortex A7 configuration early configuration
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC plat_cpu_reset_early , :
UNWIND(	.fnstart)

	mov_imm r0, 0x00000040
	write_actlr r0

	mov_imm r0, 0x00040C00
	write_nsacr r0

	bx	lr
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_early

FUNC get_core_pos_mpidr , :
UNWIND(	.fnstart)
	/* Drop ClusterId. There is no SoCs with more than 4 A7 Cores. */
	and	r0, r0, #MPIDR_CPU_MASK
	bx	lr
UNWIND(	.fnend)
END_FUNC get_core_pos_mpidr
