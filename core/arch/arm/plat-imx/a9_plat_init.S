/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 * Copyright (c) 2016, Wind River Systems.
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

#include <arm32.h>
#include <arm32_macros.S>
#include <asm.S>
#include <kernel/tz_ssvce_def.h>
#include <kernel/unwind.h>
#include <platform_config.h>

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

	/* disable PL310 ctrl */
	mov  r1, #0x0
	str  r1, [r0, #PL310_CTRL]

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
	 * Auxiliary Control Register
	 *
	 * I/Dcache prefetch enabled (bit29:28=2b11)
	 * NS can access interrupts (bit27=1)
	 * NS can lockown cache lines (bit26=1)
	 * Pseudo-random replacement policy (bit25=0)
	 * Force write allocated (default)
	 * Shared attribute internally ignored (bit22=1, bit13=0)
	 * Parity disabled (bit21=0)
	 * Event monitor disabled (bit20=0)
	 * 64kB ways, 16-way associativity (bit19:17=3b011 bit16=1)
	 * Store buffer device limitation enabled (bit11=1)
	 * Cacheable accesses have high prio (bit10=0)
	 * Full Line Zero (FLZ) disabled (bit0=0)
	 */
	movw r1, #0x0800
	movt r1, #0x3C47
	str  r1, [r0, #PL310_AUX_CTRL]

	/*
	 * Prefetch Control Register
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

	movw r1, #0xFFFF
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
	read_actlr r0
	orrne r0, r0, #(1 << 3) /* enable ACTLR[FLZW] */
	write_actlr r0

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
	 * per-CPU interrupts config are in accordance with GIC driver:
	 *
	 * ID0-ID7(SGI)   for Non-secure interrupts
	 * ID8-ID15(SGI)  for Secure interrupts.
	 * All PPI config as Non-secure interrupts.
	 *
	 * Register ICDISR0 = 0xFFFF00FF
	 *
	 * Register ICCPMR = 0x80
	 */

	ldr  r0, =GIC_DIST_BASE
	mov  r1, #0xFFFF00FF
	str  r1, [r0, #GIC_DIST_ISR0]

	ldr  r0, =GIC_CPU_BASE
	mov  r1, #0x80
	str  r1, [r0, #CORE_ICC_ICCPMR]

	mov pc, lr
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

	read_mpidr r0
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
	 * 0x00 SCUControl
	 * 0x04 SCUConfiguration
	 * 0x0C SCUInvalidateAll (Secure cfg)
	 * 0x40 FilteringStartAddress = 0x40000000
	 * 0x44 FilteeringEndAddress - 0x80000000
	 * 0x50 SCUAccessControl
	 * 0x54 SCUSecureAccessControl
	 */

	/* Invalidate all register */
	ldr  r0, =SCU_BASE
	movw r1, #0xFFFF
	movt r1, #0xFFFF
	str  r1, [r0, #SCU_INV_SEC]

	/*
	 * SCU Access Register : SAC = 0x0000000F
	 * - both secure CPU access SCU
	 */
	ldr  r0, =SCU_BASE
	movw r1, #0x000F
	movt r1, #0x0000
	str  r1, [r0, #SCU_SAC]

	/*
	 * SCU NonSecure Access Register : SNSAC : 0x00000FFF
	 * - both nonsec cpu access SCU, private and global timer
	 */
	movw r1, #0x0FFF
	movt r1, #0x0000
	str  r1, [r0, #SCU_NSAC]

	/* Enable SCU */
	ldr  r0, =SCU_BASE
	movw r2, #0x0001
	movt r2, #0x0000
	ldr  r1, [r0, #SCU_CTRL]
	orr  r1, r1, r2
	str  r1, [r0, #SCU_CTRL]

	/*
	 * Disallow NSec to mask FIQ [bit4: FW=0]
	 * Allow NSec to manage Imprecise Abort [bit5: AW=1]
	 * Imprecise Abort trapped to Abort Mode [bit3: EA=0]
	 * In Sec world, FIQ trapped to FIQ Mode [bit2: FIQ=0]
	 * IRQ always trapped to IRQ Mode [bit1: IRQ=0]
	 * Secure World [bit0: NS=0]
	 */
	mov r0, #SCR_AW
	write_scr r0		/* write Secure Configuration Register */

#if defined(PLATFORM_FLAVOR_mx6qsabrelite) || \
	defined(PLATFORM_FLAVOR_mx6qsabresd)

	/* configure imx6 CSU */

	/* first grant access of all peripherals to NS... */
	ldr r0, =CSU_CSL_START
	ldr r1, =CSU_CSL_END
	ldr r2, =0x00FF00FF

loop_csu:
	str r2, [r0]
	add r0, r0, #4
	cmp r0, r1
	bne loop_csu

	/* then restrict key peripherals */

	ldr r0, =CSU_CSL_16 /* TZASC1,TZASC2 */
	ldr r2, =0x00330033
	str r2, [r0]

	/* TODO: TZASC init */

#endif
	mov pc, lr
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_late

