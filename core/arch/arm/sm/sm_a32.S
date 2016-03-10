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

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <kernel/unwind.h>

	.section .text.sm_asm

LOCAL_FUNC sm_save_modes_regs , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	/* User mode registers has to be saved from system mode */
	cps	#CPSR_MODE_SYS
	stm	r0!, {sp, lr}

	cps	#CPSR_MODE_IRQ
	mrs	r2, spsr
	stm	r0!, {r2, sp, lr}

	cps	#CPSR_MODE_FIQ
	mrs	r2, spsr
	stm	r0!, {r2, sp, lr}

	cps	#CPSR_MODE_SVC
	mrs	r2, spsr
	stm	r0!, {r2, sp, lr}

	cps	#CPSR_MODE_ABT
	mrs	r2, spsr
	stm	r0!, {r2, sp, lr}

	cps	#CPSR_MODE_UND
	mrs	r2, spsr
	stm	r0!, {r2, sp, lr}

	cps	#CPSR_MODE_MON
	ldm	r1, {r2-r3}		/* Load SPSR and LR from the stack */
	stm	r0!, {r2-r3}		/* Store SPSR and LR in context */
	bx	lr
UNWIND(	.fnend)
END_FUNC sm_save_modes_regs

/* Restores the mode specific registers */
LOCAL_FUNC sm_restore_modes_regs , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	/* User mode registers has to be saved from system mode */
	cps	#CPSR_MODE_SYS
	ldm	r0!, {sp, lr}

	cps	#CPSR_MODE_IRQ
	ldm	r0!, {r2, sp, lr}
	msr	spsr_fsxc, r2

	cps	#CPSR_MODE_FIQ
	ldm	r0!, {r2, sp, lr}
	msr	spsr_fsxc, r2

	cps	#CPSR_MODE_SVC
	ldm	r0!, {r2, sp, lr}
	msr	spsr_fsxc, r2

	cps	#CPSR_MODE_ABT
	ldm	r0!, {r2, sp, lr}
	msr	spsr_fsxc, r2

	cps	#CPSR_MODE_UND
	ldm	r0!, {r2, sp, lr}
	msr	spsr_fsxc, r2

	cps	#CPSR_MODE_MON
	ldm	r0!, {r2-r3}		/* Load SPSR and LR from context */
	stm	r1, {r2-r3}		/* Store SPSR and LR in stack */
	bx	lr
UNWIND(	.fnend)
END_FUNC sm_restore_modes_regs

LOCAL_FUNC sm_smc_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	srsdb	sp!, #CPSR_MODE_MON
	push	{r0-r3}
/* Positions relative to stack pointer */
#define SMC_ENTRY_R0R3_OFFS	0
#define SMC_ENTRY_SRS_OFFS	(4 * 4 + SMC_ENTRY_R0R3_OFFS)

	/* Clear the exclusive monitor */
	clrex

	/* Find out if we're doing an secure or non-secure entry */
	read_scr r1
	tst	r1, #SCR_NS
	bne	.smc_ret_to_sec

.smc_ret_to_nsec:
	/* Save secure context */
	bl	sm_get_sec_ctx
	add	r1, sp, #SMC_ENTRY_SRS_OFFS /* Where srsdb wrote */
	bl	sm_save_modes_regs

	mov	r0, sp
	mov	r1, r4
	bl	sm_set_nsec_ret_vals

	/* Restore non-secure context */
	bl	sm_get_nsec_ctx
	add	r1, sp, #SMC_ENTRY_SRS_OFFS /* Where srsdb wrote */
	bl	sm_restore_modes_regs
	ldm	r0!, {r4-r12}

	/* Update SCR */
	read_scr r0
	orr	r0, r0, #(SCR_NS | SCR_FIQ) /* Set NS and FIQ bit in SCR */
	write_scr r0

	b	.smc_exit

.smc_ret_to_sec:
	bic	r1, r1, #(SCR_NS | SCR_FIQ)/* Clear NS and FIQ bit in SCR */
	write_scr r1

	/* Save non-secure context */
	push	{r12, lr}
	bl	sm_get_nsec_ctx
	pop	{r12, lr}
	add	r1, sp, #SMC_ENTRY_SRS_OFFS /* Where srsdb wrote */
	bl	sm_save_modes_regs
	stm	r0!, {r4-r12}

	/*
	 * Update secure context with vector depending on SMC function,
	 * also updates entry reason
	 */
	mov	r0, sp
	bl	sm_set_sec_smc_entry

	/* Restore secure context */
	bl	sm_get_sec_ctx
	add	r1, sp, #SMC_ENTRY_SRS_OFFS /* Where srsdb wrote */
	bl	sm_restore_modes_regs

.smc_exit:
	pop	{r0-r3}
	rfefd	sp!
UNWIND(	.fnend)
END_FUNC sm_smc_entry

/*
 * FIQ handling
 *
 * Saves CPU context in per core structure sm_pre_fiq_ctx which
 * later will be restored in the smc handler when handling a return
 * from FIQ.
 */
LOCAL_FUNC sm_fiq_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	/* FIQ has a +4 offset for lr compared to preferred return address */
	sub	lr, lr, #4
	srsdb	sp!, #CPSR_MODE_MON
	push	{r0-r3}
/* Positions relative to stack pointer */
#define FIQ_ENTRY_R0R3_OFFS	0
#define FIQ_ENTRY_SRS_OFFS	(4 * 4 + SMC_ENTRY_R0R3_OFFS)

	/* Update SCR */
	read_scr r1
	bic	r1, r1, #(SCR_NS | SCR_FIQ) /* Clear NS and FIQ bit in SCR */
	write_scr r1

	/* Save non-secure context */
	push	{r12, lr}
	bl	sm_get_nsec_ctx
	pop	{r12, lr}
	add	r1, sp, #FIQ_ENTRY_SRS_OFFS /* Where srsdb wrote */
	bl	sm_save_modes_regs
	stm	r0!, {r4-r12}
	pop	{r1-r4}	/* R0-R3 pushed at entry */
	stm	r0!, {r1-r4}

	/* Update secure context with vector for FIQ handling */
	bl	sm_set_sec_fiq_entry

	/* Restore secure context */
	bl	sm_get_sec_ctx
	mov	r1, sp	/* No offset from sp now that {R0-R3} are poped */
	bl	sm_restore_modes_regs

	rfefd	sp!
UNWIND(	.fnend)
END_FUNC sm_fiq_entry

        .align	5
LOCAL_FUNC sm_vect_table , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	b	.		/* Reset			*/
	b	.		/* Undefined instruction	*/
	b	sm_smc_entry	/* Secure monitor call		*/
	b	.		/* Prefetch abort		*/
	b	.		/* Data abort			*/
	b	.		/* Reserved			*/
	b	.		/* IRQ				*/
	b	sm_fiq_entry	/* FIQ				*/
UNWIND(	.fnend)
END_FUNC sm_vect_table

/* void sm_init(vaddr_t stack_pointer); */
FUNC sm_init , :
UNWIND(	.fnstart)
	push	{r0, lr}
UNWIND(	.save	{r0, lr})

	/* Set monitor stack */
	mrs	r1, cpsr
	cps	#CPSR_MODE_MON
	mov	sp, r0
	msr	cpsr, r1

	/* Set monitor vector (MVBAR) */
	ldr	r0, =sm_vect_table
	write_mvbar r0

	pop	{r0, pc}
UNWIND(	.fnend)
END_FUNC sm_init
