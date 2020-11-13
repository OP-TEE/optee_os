/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
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
	/*
	 * DDI: Disable dual issue [bit28=0]
	 * DDVM: Disable Distributed Virtual Memory transactions [bit15=0]
	 * L1PCTL: L1 Data prefetch control [bit14:13=2b11]
	 * L1RADIS: L1 Data Cache read-allocate mode disable [bit12=0]
	 * L2RADIS: L2 Data Cache read-allocate mode disable [bit11=0]
	 * DODMBS: Disable optimized data memory barrier behavior [bit10=0]
	 * SMP: Enables coherent requests to the processor [bit6=0]
	 */
	mov_imm r0, 0x00006040
	write_actlr r0

	mov_imm r0, 0x00040C00
	write_nsacr r0

	bx	lr
END_FUNC plat_cpu_reset_early

FUNC get_core_pos_mpidr , :
	/* Drop ClusterId. There is no SoCs with more than 4 A7 Cores. */
	and	r0, r0, #MPIDR_CPU_MASK
	bx	lr
END_FUNC get_core_pos_mpidr
