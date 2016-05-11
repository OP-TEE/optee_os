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
#include <kernel/tz_ssvce_def.h>
#include <arm32_macros.S>
#include <asm.S>
#include <platform_config.h>
#include <kernel/unwind.h>

#define CPUID_A9_R3P0_H 0x413f
#define CPUID_A9_R3P0_L 0xc090

.section .text
.balign 4
.code 32

/*
 * void arm_cl2_config(vaddr_t pl310_base) - Memory Cache Level2 Configuration
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC arm_cl2_config , :
UNWIND(	.fnstart)

	mrc  p15, 0, r2, c0, c0, 0  /* read A9 ID */
	movw r1, #CPUID_A9_R3P0_L
	movt r1, #CPUID_A9_R3P0_H
	cmp  r2, r1
	beq  _config_l2cc_r3p0
	b . /* TODO: unknown id: reset? log? */

_config_l2cc_r3p0:
	/*
	 * TAG RAM Control Register
	 *
	 * bit[10:8]:1 - 2 cycle of write accesses latency
	 * bit[6:4]:1 - 2 cycle of read accesses latency
	 * bit[2:0]:1 - 2 cycle of setup latency
	 */
	ldr  r2, [r0, #PL310_TAG_RAM_CTRL]
	movw r1, #0xf888
	movt r1, #0xffff
	and  r2,r2,r1
	movw r1, #0xf999
	movt r1, #0xffff
	orr  r2,r2,r1
	str  r2, [r0, #PL310_TAG_RAM_CTRL]

	/*
	 * DATA RAM Control Register
	 *
	 * bit[10:8]:2 - 3 cycle of write accesses latency
	 * bit[6:4]:2 - 3 cycle of read accesses latency
	 * bit[2:0]:2 - 3 cycle of setup latency
	 */
	ldr  r2, [r0, #PL310_DATA_RAM_CTRL]
	movw r1, #0xf888
	movt r1, #0xffff
	and  r2,r2,r1
	movw r1, #0xfaaa
	movt r1, #0xffff
	orr  r2,r2,r1
	str  r2, [r0, #PL310_DATA_RAM_CTRL]

	/*
	 * Auxiliary Control Register = 0x3C480800
	 *
	 * I/Dcache prefetch enabled (bit29:28=2b11)
	 * NS can access interrupts (bit27=1)
	 * NS can lockown cache lines (bit26=1)
	 * Pseudo-random replacement policy (bit25=0)
	 * Force write allocated (default)
	 * Shared attribute internally ignored (bit22=1, bit13=0)
	 * Parity disabled (bit21=0)
	 * Event monitor disabled (bit20=0)
	 * 128kB ways, 8-way associativity (bit19:17=3b100 bit16=0)
	 * Store buffer device limitation enabled (bit11=1)
	 * Cacheable accesses have high prio (bit10=0)
	 * Full Line Zero (FLZ) disabled (bit0=0)
	 */
	movw r1, #0x0800
	movt r1, #0x3C48
	str  r1, [r0, #PL310_AUX_CTRL]

	/*
	 * Prefetch Control Register = 0x31000007
	 *
	 * Double linefill disabled (bit30=0)
	 * I/D prefetch enabled (bit29:28=2b11)
	 * Prefetch drop enabled (bit24=1)
	 * Incr double linefill disable (bit23=0)
	 * Prefetch offset = 7 (bit4:0)
	 */
	movw r1, #0x0007
	movt r1, #0x3100
	str  r1, [r0, #PL310_PREFETCH_CTRL]

	/*
	 * Power Register = 0x00000003
	 *
	 * Dynamic clock gating enabled
	 * Standby mode enabled
	 */
	movw r1, #0x0003
	movt r1, #0x0000
	str  r1, [r0, #PL310_POWER_CTRL]

	/* invalidate all cache ways */
	movw r1, #0x00FF
	movt r1, #0x0000
	str  r1, [r0, #PL310_INV_BY_WAY]

	mov pc, lr
UNWIND(	.fnend)
END_FUNC arm_cl2_config
/* End of arm_cl2_config */


/*
 * void arm_cl2_enable(vaddr_t pl310_base) - Memory Cache Level2 Enable Function
 *
 * If PL310 supports FZLW, enable also FZL in A9 core
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 * TODO: to be moved to PL310 code (tz_svce_pl310.S ?)
 */
FUNC arm_cl2_enable , :
UNWIND(	.fnstart)


	/* Enable PL310 ctrl -> only set lsb bit */
	mov  r1, #0x1
	str  r1, [r0, #PL310_CTRL]

	/* if L2 FLZW enable, enable in L1 */
	ldr  r1, [r0, #PL310_AUX_CTRL]
	tst  r1, #(1 << 0) /* test AUX_CTRL[FLZ] */
	mrc  p15, 0, r0, c1, c0, 1
	orrne r0, r0, #(1 << 3) /* enable ACTLR[FLZW] */
	mcr  p15, 0, r0, c1, c0, 1

	mov pc, lr
UNWIND(	.fnend)
END_FUNC arm_cl2_enable

/* 
 * Cortex A9 configuration early configuration
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC plat_cpu_reset_early , :
UNWIND(	.fnstart)

	/* only r3p0 is supported */
	mrc  p15, 0, r0, c0, c0, 0  /* read A9 ID */
	movw r1, #CPUID_A9_R3P0_L
	movt r1, #CPUID_A9_R3P0_H
	cmp  r0, r1
	beq  _early_a9_r3p0
	b . /* TODO: unknown id: reset? log? */

_early_a9_r3p0:
	/*
	 * Mandated HW config loaded
	 *
	 * SCTLR = 0x00004000
	 * - Round-Robin replac. for icache, btac, i/duTLB (bit14: RoundRobin)
	 *
	 * ACTRL = 0x00000041
	 * - core always in full SMP (FW bit0=1, SMP bit6=1)
	 * - L2 write full line of zero disabled (bit3=0)
	 *   (keep WFLZ low. Will be set once outer L2 is ready)
	 *
	 * NSACR = 0x00020C00
	 * - NSec cannot change ACTRL.SMP (NS_SMP bit18=0)
	 * - Nsec can lockdown TLB (TL bit17=1)
	 * - NSec cannot access PLE (PLE bit16=0)
	 * - NSec can use SIMD/VFP (CP10/CP11) (bit15:14=2b00, bit11:10=2b11)
	 *
	 * PCR = 0x00000001
	 * - no change latency, enable clk gating
	 */
	movw r0, #0x4000
	movt r0, #0x0000
	write_sctlr r0

	movw r0, #0x0041
	movt r0, #0x0000
	write_actlr r0

	movw r0, #0x0C00
	movt r0, #0x0002
	write_nsacr r0

	movw r0, #0x0000
	movt r0, #0x0001
	write_pcr r0

	/*
	 * GIC configuration
	 *
	 * Register ICDISR0 = 0xFFFFFFFF
	 * - All local interrupts are NonSecure.
	 *
	 * Register ICCPMR = 0xFFFFFFFF
	 */

	ldr  r0, =GIC_DIST_BASE
	mov  r1, #0xFFFFFFFF
	str  r1, [r0, #GIC_DIST_ISR0]

	ldr  r0, =GIC_CPU_BASE
	mov  r1, #0xFFFFFFFF
	str  r1, [r0, #CORE_ICC_ICCPMR]

	mov pc, lr /* back to tzinit */
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_early

/*
 * A9 secured config, needed only from a single core
 *
 * Use scratables registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 *
 * TODO: size optim in code
 */
FUNC plat_cpu_reset_late , :
UNWIND(	.fnstart)

	mrc p15, 0, r0, c0, c0, 5
	ands r0, #3
	beq _boot_late_primary_cpu

_boot_late_secondary_cpu:
	mov pc, lr

_boot_late_primary_cpu:
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
	 * SCU Access Register : SAC = 0x00000003
	 * - both secure CPU access SCU
	 */
	ldr  r0, =SCU_BASE
	movw r1, #0x0003
	movt r1, #0x0000
	str  r1, [r0, #SCU_SAC]

	/*
	 * SCU NonSecure Access Register : SNSAC : 0x00000333
	 * - both nonsec cpu access SCU, private and global timer
	 */
	movw r1, #0x0333
	movt r1, #0x0000
	str  r1, [r0, #SCU_NSAC]

	/*
	 * SCU Filtering End Address register: SFEA
	 */
	movw r1, #(CPU_PORT_FILT_END & 0xFFFF)
	movt r1, #(CPU_PORT_FILT_END >> 16)
	str  r1, [r0, #SCU_FILT_EA]

	/*
	 * SCU Filtering Start Address register: SFSA
	 */
	movw r1, #(CPU_PORT_FILT_START & 0xFFFF)
	movt r1, #(CPU_PORT_FILT_START >> 16)
	str  r1, [r0, #SCU_FILT_SA]

	/*
	 * SCU Control Register : CTRL = 0x00000065
	 * - ic stanby enable=1
	 * - scu standby enable=1
	 * - scu enable=1
	 */
	movw r1, #0x0065
	movt r1, #0x0000
	str	 r1, [r0, #SCU_CTRL]

	/*- GIC secure configuration ---*/

	/*
	 * Register ICDISR[1-31] = 0xFFFFFFFF
	 * - All external interrupts are NonSecure.
	 */
	ldr  r0, =(GIC_DIST_BASE + GIC_DIST_ISR1)
	mov  r2, #0xFFFFFFFF
	mov  r1, #31 /* Nb of loop rounds */
loop_1:
	str r2, [r0]
	add r0, #4
	sub r1, r1, #1
	cmp r1, #0
	bne loop_1


	/*- PL310 Memory Controller (Note: should be done with NS=1) ---*/
	/* Note: we're in secure mode with mmu disabled => NS=0 */

	/*
	 * reg12_addr_filtering_end
	 */
	ldr  r0, =PL310_BASE
	movw r1, #(CPU_PORT_FILT_END & 0xFFFF)
	movt r1, #(CPU_PORT_FILT_END >> 16)
	str  r1, [r0, #PL310_ADDR_FILT_END]

	/*
	 * reg12_addr_filtering_start
	 */
	movw r1, #((CPU_PORT_FILT_START & 0xFFFF) | 1)
	movt r1, #(CPU_PORT_FILT_START >> 16)
	str  r1, [r0, #PL310_ADDR_FILT_START]

	/* Allow NSec to manage FIQ/Imprecise abort */
	mrc p15, 0, r0, c1, c1, 0    /* read Secure Configuration Register */
	orr r0, r0, #0x30            /* SCR[FW]=1, SCR[AW]=1 */
	mcr p15, 0, r0, c1, c1, 0    /* write updated value in Secure Configuration Register */

	mov pc, lr
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_late
