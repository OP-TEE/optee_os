/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2016, STMicroelectronics International N.V.
 */

#include <arm32.h>
#include <arm32_macros.S>
#include <arm32_macros_cortex_a9.S>
#include <asm.S>
#include <kernel/tz_ssvce_def.h>
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
	/* CPSR.A can be modified in any security state. */
	mov_imm	r0, SCR_AW
	write_scr r0

	mov_imm r0, CPU_SCTLR_INIT
	write_sctlr r0

	mov_imm r0, CPU_ACTLR_INIT
	write_actlr r0

	mov_imm r0, CPU_NSACR_INIT
	write_nsacr r0

	mov_imm r0, CPU_PCR_INIT
	write_pcr r0

	mov pc, lr
END_FUNC plat_cpu_reset_early

