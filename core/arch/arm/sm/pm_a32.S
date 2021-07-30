/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <arm32_macros_cortex_a9.S>
#include <arm32_macros.S>
#include <arm.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/asan.h>
#include <platform_config.h>

.section .text

/*
 * int sm_pm_cpu_suspend(uint32_t arg, int (*fn)(uint32_t))
 * @arg will be passed to fn as argument
 * return value: 0 - cpu resumed from suspended state.
 *		 -1 - cpu not suspended.
 */
FUNC sm_pm_cpu_suspend, :
UNWIND(	.cantunwind)
	push	{r4 - r12, lr}
	mov	r5, sp
	sub	sp, sp, #SM_PM_CTX_SIZE
	push	{r0, r1}

	mov	r1, r5
	add	r0, sp, #8
	blx	sm_pm_cpu_suspend_save
	adr	lr, aborted
	/* Jump to arch specific suspend */
	pop	{r0, pc}
aborted:
	/* cpu not suspended */
	add	sp, sp, #SM_PM_CTX_SIZE
	/* Return -1 to the caller */
	mov	r0, #(-1)
suspend_return:
	pop	{r4 - r12, pc}
END_FUNC sm_pm_cpu_suspend

FUNC sm_pm_cpu_do_suspend, :
UNWIND(	.cantunwind)
	push	{r4 - r11}
	read_midr r4
	ubfx	r5, r4, #4, #12
	ldr     r4, =CORTEX_A5_PART_NUM
	cmp	r5, r4
	beq	a5_a7_suspend
	ldr     r4, =CORTEX_A7_PART_NUM
	cmp	r5, r4
	beq	a5_a7_suspend
	ldr     r4, =CORTEX_A9_PART_NUM
	cmp	r5, r4
	beq	a9_suspend
	/* cpu not supported */
	b	.
	/* A9 needs PCR/DIAG */
a9_suspend:
	read_pcr r4
	read_diag r5
	stmia	r0!, {r4 - r5}
a5_a7_suspend:
	read_fcseidr r4
	read_tpidruro r5
	stmia	r0!, {r4 - r5}
	read_dacr r4
#ifdef CFG_WITH_LPAE
#error "Not supported"
#else
	read_ttbr0 r5
	read_ttbr1 r6
	read_ttbcr r7
#endif
	read_sctlr r8
	read_actlr r9
	read_cpacr r10
	read_mvbar r11
	stmia	r0!, {r4 - r11}
	read_prrr r4
	read_nmrr r5
	read_vbar r6
	read_nsacr r7
	stmia	r0, {r4 - r7}
	pop	{r4 - r11}
	bx	lr
END_FUNC sm_pm_cpu_do_suspend

FUNC sm_pm_cpu_resume, :
UNWIND(	.cantunwind)
	cpsid	aif

	/* Call into the runtime address of __get_core_pos */
	adr	r0, _core_pos
	ldr	r1, [r0]
	add	r0, r0, r1
	blx	r0

	/*
	 * At this point, MMU is not enabled now.
	 * 1. Get the runtime physical address of _suspend_sp
	 * 2. Get the offset from _suspend_sp to &thread_core_local
	 * 3. Get the runtime physical address of thread_core_local
	 * Since moving towards non-linear mapping,
	 * `ldr r0, =thread_core_local` is not used here.
	 */
	adr	r4, _suspend_sp
	ldr	r5, [r4]
	add	r4, r4, r5

	mov_imm r1, THREAD_CORE_LOCAL_SIZE
	mla	r0, r0, r1, r4

	ldr	r0, [r0, #THREAD_CORE_LOCAL_SM_PM_CTX_PHYS]
	/* Need to use r0!, because sm_pm_cpu_do_resume needs it */
	ldmia	r0!, {sp, pc}
END_FUNC sm_pm_cpu_resume

/*
 * The following will be located in text section whose attribute is
 * marked as readonly, but we only need to read here
 * _suspend_sp stores the offset between thread_core_local to _suspend_sp.
 * _core_pos stores the offset between __get_core_pos to _core_pos.
 */
.align 2
.extern thread_core_local
_suspend_sp:
	.long	thread_core_local - .
.extern __get_core_pos
_core_pos:
	.long	__get_core_pos - .

/*
 * void sm_pm_cpu_do_resume(paddr suspend_regs) __noreturn;
 * Restore the registers stored when sm_pm_cpu_do_suspend
 * r0 points to the physical base address of the suspend_regs
 * field of struct sm_pm_ctx.
 */
FUNC sm_pm_cpu_do_resume, :
UNWIND(	.cantunwind)
	read_midr r4
	ubfx	r5, r4, #4, #12
	ldr     r4, =CORTEX_A5_PART_NUM
	cmp	r5, r4
	beq	a5_a7_resume
	ldr     r4, =CORTEX_A7_PART_NUM
	cmp	r5, r4
	beq	a5_a7_resume

	/*
	 * A9 needs PCR/DIAG
	 */
	ldmia   r0!, {r4 - r5}
	write_pcr r4
	write_diag r5

a5_a7_resume:
	/* v7 resume */
	mov	ip, #0
	/* Invalidate icache to PoU */
	write_iciallu
	/* set reserved context */
	write_contextidr ip
	ldmia	r0!, {r4 - r5}
	write_fcseidr r4
	write_tpidruro r5
	ldmia	r0!, {r4 - r11}
	/* Invalidate entire TLB */
	write_tlbiall
	write_dacr r4
#ifdef CFG_WITH_LPAE
#error "Not supported -"
#else
	write_ttbr0 r5
	write_ttbr1 r6
	write_ttbcr r7
#endif

	ldmia	r0, {r4 - r7}
	write_prrr r4
	write_nmrr r5
	write_vbar r6
	write_nsacr r7

	write_actlr r9
	write_cpacr r10
	write_mvbar r11
	write_bpiall
	isb
	dsb
	/* MMU will be enabled here */
	write_sctlr r8
	isb
	mov	r0, #0
	b	suspend_return
END_FUNC sm_pm_cpu_do_resume

