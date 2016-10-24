/*
 * Copyright (c) 2014-2016, STMicroelectronics International N.V.
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

	mov pc, lr

UNWIND(	.fnend)
END_FUNC plat_cpu_reset_early

