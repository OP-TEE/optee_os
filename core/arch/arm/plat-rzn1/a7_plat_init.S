/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Wind River Systems.
 * Copyright (c) 2020, Linaro Limited
 */

/*
 * Entry points for the A7 init.
 *
 * Assumptions:
 * - No stack is available when these routines are called.
 * - Each routine is called with return address in LR and
 *   with ARM registers R0, R1, R2, R3 being scratchable.
 */

#include <arm32.h>
#include <arm32_macros.S>
#include <asm.S>
#include <platform_config.h>

.section .text
.balign 4
.code 32

FUNC plat_cpu_reset_early , :
	/*
	 * SCR = 0x00000020
	 * - FW: Disallow NSec to mask FIQ [bit4=0]
	 * - AW: Allow NSec to manage Imprecise Abort [bit5=1]
	 * - EA: Imprecise Abort trapped to Abort Mode [bit3=0]
	 * - FIQ: In Sec world, FIQ trapped to FIQ Mode [bit2=0]
	 * - IRQ: IRQ always trapped to IRQ Mode [bit1=0]
	 * - NS: Secure World [bit0=0]
	 */
	mov r0, #SCR_AW
	write_scr r0

	mov_imm r0, 0x00000000
	write_sctlr r0

	/*
	 * ACTRL = 0x00006040
	 * - DDI: Disable dual issue [bit28=0]
	 * - DDVM: Disable Distributed Virtual Memory transactions [bit15=0]
	 * - L1PCTL: L1 Data prefetch control [bit14:13=2b11]
	 * - L1RADIS: L1 Data Cache read-allocate mode disable [bit12=0]
	 * - L2RADIS: L2 Data Cache read-allocate mode disable [bit11=0]
	 * - DODMBS: Disable optimized data memory barrier behavior [bit10=0]
	 * - SMP: Enables coherent requests to the processor [bit6=0]
	 */
	mov_imm r0, 0x00006040
	write_actlr r0

	/*
	 * NSACR = 0x00000C00
	 * - NS_SMP: Non-secure mode cannot change ACTRL.SMP (bit18=0)
	 * - NSASEDIS/NSD32DIS/CP10/CP11: Non-secure mode can use SIMD/VFP
	 *                                (bit15:14=2b00, bit11:10=2b11)
	 */
	mov_imm r0, 0x00000C00
	write_nsacr r0

	mov pc, lr
END_FUNC plat_cpu_reset_early
