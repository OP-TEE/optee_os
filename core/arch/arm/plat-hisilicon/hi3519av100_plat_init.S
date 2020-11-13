/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, HiSilicon Technologies Co., Ltd.
 */

/*
 * Entry points for the Hi3519AV100 a53 aarch32 mode init.
 * It is assumed no stack is available when these routines are called.
 * It is assumed each routine is called with return address in LR
 * and with ARM registers R0, R1, R2, R3 being scratched.
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <platform_config.h>

#define CCI_BASE		0x04528000
#define CPUECTLR_A53_SMPEN	BIT(6)
#define ACTRL_CPUECTLR		BIT(1)
#define HACTRL_CPUECTLR		BIT(1)

.section .text
.balign 4
.code 32

/*
 * Hi3519AV100 a53 aarch32 configuration early configuration
 *
 * Use scratch registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC plat_cpu_reset_early , :
	/*
	 * Write the CPU Extended Control Register
	 * Set the SMPEN bit, this Cortex-A53 core's register
	 */
	mrrc	p15, 1, r0, r1, c15
	orr	r0, r0, #CPUECTLR_A53_SMPEN
	mcrr	p15, 1, r0, r1, c15

	/*
	 * Enable Non-Secure EL1 write access to CPUECTLR
	 */
	mrs	r1, cpsr
	cps	#CPSR_MODE_MON

	read_scr r0
	orr	r0, r0, #SCR_NS /* Set NS bit in SCR */
	write_scr r0
	isb

	/* Write HACTLR register */
	mrc	p15, 4, r2, c1, c0, 1
	orr	r2, r2, #HACTRL_CPUECTLR
	mcr	p15, 4, r2, c1, c0, 1

	bic	r0, r0, #SCR_NS /* Clr NS bit in SCR */
	write_scr r0
	isb

	/* Write ACTLR register */
	mrc	p15, 0, r2, c1, c0, 1
	orr	r2, r2, #ACTRL_CPUECTLR
	mcr	p15, 0, r2, c1, c0, 1

	msr	cpsr, r1
	/*
	 * Enable cci for secondary core
	 */
	mov	r3, lr
	bl	__get_core_pos
	mov	lr, r3
	cmp	r0, #0
	beq	out
	ldr	r0, =CCI_BASE
	ldr	r1, [r0]
	orr	r1, r1, #BIT(9)   /* bit 9 set to 1 */
	str	r1, [r0]
out:
	bx	lr
END_FUNC plat_cpu_reset_early
