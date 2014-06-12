/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Entry points for the A9 inits, A9 revision specific or not.
 * It is assume no stack is available when these routines are called.
 * It is assume each routine is called with return address in LR
 * and with ARM registers R0, R1, R2, R3 being scratchable.
 */

.global arm_secboot_identify_cpu
.global arm_secboot_early
.global arm_secboot_errata
.global arm_cl2_config
.global arm_cl2_enable
.global arm_secboot_late

#define CPUID_A9_R2P2_H 0x412f
#define CPUID_A9_R2P2_L 0xc092

#define CPUID_A9_R3P0_H 0x413f
#define CPUID_A9_R3P0_L 0xc090

.section .text
.balign 4
.code 32

/*
 * arm_secboot_identify_cpu - identify and save CPU version
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
.func arm_secboot_identify_cpu
arm_secboot_identify_cpu:

	mrc  p15, 0, r0, c0, c0, 0  /* read A9 ID */
	movw r1, #CPUID_A9_R2P2_L
	movt r1, #CPUID_A9_R2P2_H
	cmp  r0, r1
	beq  _ident_a9_r2p2
	movw r1, #CPUID_A9_R3P0_L
	movt r1, #CPUID_A9_R3P0_H
	cmp  r0, r1
	beq  _ident_a9_r3p0
	b . /* TODO: unknown id: reset? log? */

_ident_a9_r2p2:
	/* unsupported version. TODO: needs to be supported */
	b . /* TODO: unknown id: reset? log? */

_ident_a9_r3p0:
	mov pc, lr /* back to tzinit */

.endfunc

/*
 * Memory Cache Level2 Configuration Function
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
.func arm_cl2_config
arm_cl2_config:

	mrc  p15, 0, r0, c0, c0, 0  /* read A9 ID */
	movw r1, #CPUID_A9_R3P0_L
	movt r1, #CPUID_A9_R3P0_H
	cmp  r0, r1
	beq  _config_l2cc_r3p0
	b . /* TODO: unknown id: reset? log? */

_config_l2cc_r3p0:
	/*
	 * reg1_tag_ram_control (cache_l2x0.c)
	 * bit[10:8]:1 - 2 cycle of write accesses latency
	 * bit[6:4]:1 - 2 cycle of read accesses latency
	 * bit[2:0]:1 - 2 cycle of setup latency
	 */
	movw r0, #0x2108
	movt r0, #0xFFFE
	ldr  r2, [r0]
	movw r1, #0xf888
	movt r1, #0xffff
	and  r2,r2,r1
	movw r1, #0xf999
	movt r1, #0xffff
	orr  r2,r2,r1
	str  r2, [r0]

	/*
	 * reg1_data_ram_control (cache_l2x0.c)
	 * bit[10:8]:2 - 3 cycle of write accesses latency
	 * bit[6:4]:2 - 3 cycle of read accesses latency
	 * bit[2:0]:2 - 3 cycle of setup latency
	 */
	movw r0, #0x210C
	movt r0, #0xFFFE
	ldr  r2, [r0]
	movw r1, #0xf888
	movt r1, #0xffff
	and  r2,r2,r1
	movw r1, #0xfaaa
	movt r1, #0xffff
	orr  r2,r2,r1
	str  r2, [r0]

	/*
	 * reg1_aux_control
	 */
	movw r0, #0x2104
	movt r0, #0xFFFE
	movw r1, #0x0801
	movt r1, #0x3C48
	str  r1, [r0]

	/*
	 * reg15_prefetch_ctrl
	 */
	movw r0, #0x2F60
	movt r0, #0xFFFE
	movw r1, #0x0000
	movt r1, #0x3100
	str  r1, [r0]

	/*
	 * reg15_power_ctrl
	 */
	movw r0, #0x2F80
	movt r0, #0xFFFE
	movw r1, #0x0003
	movt r1, #0x0000
	str  r1, [r0]

	/* invalidate all cache ways PL310_BASE + invalidate by way offset = 0xFFFE2000 + 0x77C) */
	movw r0, #0x277C
	movt r0, #0xFFFE
	movw r1, #0x00FF
	movt r1, #0x0000
	str  r1, [r0]

	mov pc, lr

.endfunc
/* End of arm_cl2_config */


/*
 * Memory Cache Level2 Enable Function
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
.func arm_cl2_enable
arm_cl2_enable:

	/* Enable L2 ctrl (PL310_BASE + L2x0_CTRL = 0xFFFE2000 + 0x100) --> only set lsb bit */
	movw r0, #0x2100
	movt r0, #0xFFFE
	movw r1, #0x0001
	movt r1, #0x0000
	str  r1, [r0]

	mov pc, lr

.endfunc
/* End of arm_cl2_enable */

/* 
 * Cortex A9 configuration early configuration
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
.func arm_secboot_early
arm_secboot_early:

	/* only r3p0 is supported */
	mrc  p15, 0, r0, c0, c0, 0  /* read A9 ID */
	movw r1, #CPUID_A9_R3P0_L
	movt r1, #CPUID_A9_R3P0_H
	cmp  r0, r1
	beq  _early_a9_r3p0
	b . /* TODO: unknown id: reset? log? */

_early_a9_r3p0:
	/*
	 * Register SCTLR
	 * RR Bit[14]=1
	 */
	movw r0, #0x4000
	movt r0, #0x0000
	mcr  p15, 0, r0, c1, c0, 0

	/*
	 * Register ACTLR
	 * FW Bit[0]=1
	 * WFLZ Bit[3]=1
	 * SMP Bit[6]=1
	 */
	movw r0, #0x0049
	movt r0, #0x0000
	mcr  p15, 0, r0, c1, c0, 1

	/*
	 * Register NSACR
	 * TL	Bit[17]=1
	 * CPU11 Bit[11]=1
	 * CPU10 Bit[10]=1
	 */
	movw r0, #0x0C00
	movt r0, #0x0002
	mcr  p15, 0, r0, c1, c1, 2

	/*
	 * Register PCR
	 * ECG   Bit[0]=1
	 */
	movw r0, #0x0000
	movt r0, #0x0001
	mcr  p15, 0, r0, c15, c0, 0

	/*
	 * GIC configuration
	 */
	/*
	 * Register ICDISR0
	 */
	movw r0, #0x1080
	movt r0, #0xFFFE
	mov  r1, #0xFFFFFFFF
	str  r1, [r0]

	/*
	 * Register ICCPMR
	 */
	movw r0, #0x0104
	movt r0, #0xFFFE
	mov  r1, #0xFFFFFFFF
	str  r1, [r0]

	mov pc, lr /* back to tzinit */

.endfunc

/*
 * arm_secboot_errata - arm errata, specific per core revision
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
.func arm_secboot_errata
arm_secboot_errata:

	mrc  p15, 0, r0, c0, c0, 0  /* read A9 ID */
	movw r1, #CPUID_A9_R2P2_L
	movt r1, #CPUID_A9_R2P2_H
	cmp  r0, r1
	beq  _errata_a9_r2p2
	movw r1, #CPUID_A9_R3P0_L
	movt r1, #CPUID_A9_R3P0_H
	cmp  r0, r1
	beq  _errata_a9_r3p0
	b . /* TODO: unknown id: reset? log? */

_errata_a9_r2p2:
	/* unsupported version. TODO: needs to be supported */
	b . /* TODO: unknown id: reset? log? */

_errata_a9_r3p0:
	mov pc, lr

.endfunc

/*
 * A9 secured config, needed only from a single core
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
.func arm_secboot_late
arm_secboot_late:

	/*
	 * Snoop Control Unit configuration
	 *
	 * SCU is enabled with filtering off.
	 * Both Secure/Unsecure can access SCU and timers
	 *
	 * 0x00 SCUControl = 0x00000060 !!!  should be 0x5 !   A NETTOYER !!!!!!!!!!!!!!!!!!!!!!!!!
	 * 0x04 SCUConfiguration =  ???                        A NETTOYER !!!!!!!!!!!!!!!!!!!!!!!!!
	 * 0x0C SCUInvalidateAll (Secure cfg)
	 * 0x40 FilteringStartAddress = 0x40000000
	 * 0x44 FilteeringEndAddress - 0x80000000
	 * 0x50 SCUAccessControl
	 * 0x54 SCUSecureAccessControl
	 */

	/*
	 * Register SAC: both secure CPU access SCU
	 */
	movw r0, #0x0050 /* LSB */
	movt r0, #0xFFFE /* MSB */
	movw r1, #0x0003
	movt r1, #0x0000
	str  r1, [r0]

	/*
	 * Register SNSAC: both nonsec cpu access SCU, private and global timer
	 */
	movw r0, #0x0054 /* LSB */
	movt r0, #0xFFFE /* MSB */
	movw r1, #0x0333
	movt r1, #0x0000
	str  r1, [r0]

	/*
	 * Register SFEA
	 */
	movw r0, #0x0044 /* LSB */
	movt r0, #0xFFFE /* MSB */
	movw r1, #0x0000
	movt r1, #0x8000
	str  r1, [r0]

	/*
	 * Register SFSA
	 */
	movw r0, #0x0040 /* LSB */
	movt r0, #0xFFFE /* MSB */
	movw r1, #0x0000
	movt r1, #0x4000
	str  r1, [r0]

	/*
	 * Register SCU_CTRL
	 */
	movw r0, #0x0000 /* LSB */
	movt r0, #0xFFFE /* MSB */
	movw r1, #0x0065
	movt r1, #0x0000
	str	 r1, [r0]

	/*- GIC secure configuration ---*/

	/*
	 * Register ICDISR[0-31]
	 */
	movw r0, #0x1084
	movt r0, #0xFFFE
	mov  r2, #0xFFFFFFFF
	mov  r1, #31 /* Nb of loop rounds */
loop_1:
	str r2, [r0]
	add r0, #4
	sub r1, r1, #1
	cmp r1, #0
	bne loop_1


	/*- L2 Memory Controller (Note: should be done with NS=1) ---*/

	/*
	 * reg12_addr_filtering_end
	 */
	movw r0, #0x2C04
	movt r0, #0xFFFE
	movw r1, #0x0000
	movt r1, #0x8000
	str  r1, [r0]

	/*
	 * reg12_addr_filtering_start
	 */
	movw r0, #0x2C00
	movt r0, #0xFFFE
	movw r1, #0x0001
	movt r1, #0x4000
	str  r1, [r0]

	/* Allow NSec to manage FIQ/Imprecise abort */
	mrc p15, 0, r0, c1, c1, 0    /* read Secure Configuration Register */
	orr r0, r0, #0x30            /* SCR[FW]=1, SCR[AW]=1 */
	mcr p15, 0, r0, c1, c1, 0    /* write updated value in Secure Configuration Register */

	mov pc, lr

.endfunc

