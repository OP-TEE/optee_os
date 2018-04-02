/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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
#include <arm32_macros_cortex_a9.S>
#include <asm.S>
#include <kernel/tz_ssvce_def.h>
#include <kernel/unwind.h>
#include <platform_config.h>

.section .text
.balign 4
.code 32

/*
 * Cortex A9 early configuration
 *
 * Use registers R0-R3.
 * No stack usage.
 * LR store return address.
 * Trap CPU in case of error.
 */
FUNC plat_cpu_reset_early , :
UNWIND(	.fnstart)

	/*
	 * Disallow NSec to mask FIQ [bit4: FW=0]
	 * Allow NSec to manage Imprecise Abort [bit5: AW=1]
	 * Imprecise Abort trapped to Abort Mode [bit3: EA=0]
	 * In Sec world, FIQ trapped to FIQ Mode [bit2: FIQ=0]
	 * IRQ always trapped to IRQ Mode [bit1: IRQ=0]
	 * Secure World [bit0: NS=0]
	 */
	mov r0, #SCR_AW
	write_scr r0

	/*
	 * Mandated HW config loaded
	 *
	 * SCTLR = 0x00004000
	 * - Round-Robin replac. for icache, btac, i/duTLB (bit14: RoundRobin)
	 *
	 * ACTRL = 0x000000[46(i.MX6SLL),47]
	 * - core always in full SMP (FW bit0=[0(i.MX6SLL),1], SMP bit6=1)
	 * - L2 write full line of zero disabled (bit3=0)
	 *   (keep WFLZ low. Will be set once outer L2 is ready)
	 * - L1 Prefetch enable (bit2=1)
	 * - L2 Prefetch hint enable (bit1=1)
	 *
	 * NSACR = 0x00020C00
	 * - NSec cannot change ACTRL.SMP (NS_SMP bit18=0)
	 * - Nsec can lockdown TLB (TL bit17=1)
	 * - NSec cannot access PLE (PLE bit16=0)
	 * - NSec can use SIMD/VFP (CP10/CP11) (bit15:14=2b00, bit11:10=2b11)
	 *
	 * PCR
	 * - no change latency, enable clk gating
	 */
	mov_imm r0, 0x00004000
	write_sctlr r0

#ifdef CFG_MX6SLL
	mov_imm r0, 0x00000046
#else
	mov_imm r0, 0x00000047
#endif
	write_actlr r0

	mov_imm r0, 0x00020C00
	write_nsacr r0

	read_pcr r0
	orr r0, r0, #0x1
	write_pcr r0

	mov pc, lr
UNWIND(	.fnend)
END_FUNC plat_cpu_reset_early
