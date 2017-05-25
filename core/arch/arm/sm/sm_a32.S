/*
 * Copyright (c) 2016, Linaro Limited
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

#include <arm32_macros.S>
#include <arm.h>
#include <asm-defines.h>
#include <asm.S>
#include <keep.h>
#include <kernel/unwind.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

	.section .text.sm_asm

FUNC sm_save_modes_regs , :
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
	bx	lr
UNWIND(	.fnend)
END_FUNC sm_save_modes_regs

/* Restores the mode specific registers */
FUNC sm_restore_modes_regs , :
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
	bx	lr
UNWIND(	.fnend)
END_FUNC sm_restore_modes_regs

/*
 * stack_tmp is used as stack, the top of the stack is reserved to hold
 * struct sm_ctx, everything below is for normal stack usage. As several
 * different CPU modes are using the same stack it's important that switch
 * of CPU mode isn't done until one mode is done. This means FIQ, IRQ and
 * Async abort has to be masked while using stack_tmp.
 */
LOCAL_FUNC sm_smc_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	srsdb	sp!, #CPSR_MODE_MON
	push	{r0-r7}

	clrex		/* Clear the exclusive monitor */

	/* Find out if we're doing an secure or non-secure entry */
	read_scr r1
	tst	r1, #SCR_NS
	bne	.smc_from_nsec

	/*
	 * As we're coming from secure world (NS bit cleared) the stack
	 * pointer points to sm_ctx.sec.r0 at this stage. After the
	 * instruction below the stack pointer points to sm_ctx.
	 */
	sub	sp, sp, #(SM_CTX_SEC + SM_SEC_CTX_R0)

	/* Save secure context */
	add	r0, sp, #SM_CTX_SEC
	bl	sm_save_modes_regs

	/*
	 * On FIQ exit we're restoring the non-secure context unchanged, on
	 * all other exits we're shifting r1-r4 from secure context into
	 * r0-r3 in non-secure context.
	 */
	add	r8, sp, #(SM_CTX_SEC + SM_SEC_CTX_R0)
	ldm	r8, {r0-r4}
	mov_imm	r9, TEESMC_OPTEED_RETURN_FIQ_DONE
	cmp	r0, r9
	addne	r8, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R0)
	stmne	r8, {r1-r4}

	/* Restore non-secure context */
	add	r0, sp, #SM_CTX_NSEC
	bl	sm_restore_modes_regs

.sm_ret_to_nsec:
	/*
	 * Return to non-secure world
	 */
	add     r0, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R8)
	ldm	r0, {r8-r12}

	/* Update SCR */
	read_scr r0
	orr	r0, r0, #(SCR_NS | SCR_FIQ) /* Set NS and FIQ bit in SCR */
	write_scr r0

	add	sp, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R0)
	b	.sm_exit

.smc_from_nsec:
	/*
	 * As we're coming from non-secure world (NS bit set) the stack
	 * pointer points to sm_ctx.nsec.r0 at this stage. After the
	 * instruction below the stack pointer points to sm_ctx.
	 */
	sub	sp, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R0)

	bic	r1, r1, #(SCR_NS | SCR_FIQ) /* Clear NS and FIQ bit in SCR */
	write_scr r1

	add	r0, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R8)
	stm	r0, {r8-r12}

	mov	r0, sp
	bl	sm_from_nsec
	cmp	r0, #0
	beq	.sm_ret_to_nsec

	/*
	 * Continue into secure world
	 */
	add	sp, sp, #(SM_CTX_SEC + SM_SEC_CTX_R0)

.sm_exit:
	pop	{r0-r7}
	rfefd	sp!
UNWIND(	.fnend)
END_FUNC sm_smc_entry

/*
 * FIQ handling
 *
 * Saves CPU context in the same way as sm_smc_entry() above. The CPU
 * context will later be restored by sm_smc_entry() when handling a return
 * from FIQ.
 */
LOCAL_FUNC sm_fiq_entry , :
UNWIND(	.fnstart)
UNWIND(	.cantunwind)
	/* FIQ has a +4 offset for lr compared to preferred return address */
	sub	lr, lr, #4
	/* sp points just past struct sm_sec_ctx */
	srsdb	sp!, #CPSR_MODE_MON
	push	{r0-r7}

	clrex		/* Clear the exclusive monitor */

	/*
	 * As we're coming from non-secure world the stack pointer points
	 * to sm_ctx.nsec.r0 at this stage. After the instruction below the
	 * stack pointer points to sm_ctx.
	 */
	sub	sp, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R0)

	/* Update SCR */
	read_scr r1
	bic	r1, r1, #(SCR_NS | SCR_FIQ) /* Clear NS and FIQ bit in SCR */
	write_scr r1

	/* Save non-secure context */
	add	r0, sp, #SM_CTX_NSEC
	bl	sm_save_modes_regs
	stm	r0!, {r8-r12}

	/* Set FIQ entry */
	ldr	r0, =(thread_vector_table + THREAD_VECTOR_TABLE_FIQ_ENTRY)
	str	r0, [sp, #(SM_CTX_SEC + SM_SEC_CTX_MON_LR)]

	/* Restore secure context */
	add	r0, sp, #SM_CTX_SEC
	bl	sm_restore_modes_regs

	add	sp, sp, #(SM_CTX_SEC + SM_SEC_CTX_MON_LR)

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
	/* Set monitor stack */
	mrs	r1, cpsr
	cps	#CPSR_MODE_MON
	/* Point just beyond sm_ctx.sec */
	sub	sp, r0, #(SM_CTX_SIZE - SM_CTX_NSEC)
	msr	cpsr, r1

	/* Set monitor vector (MVBAR) */
	ldr	r0, =sm_vect_table
	write_mvbar r0

	bx	lr
END_FUNC sm_init
KEEP_PAGER sm_init


/* struct sm_nsec_ctx *sm_get_nsec_ctx(void); */
FUNC sm_get_nsec_ctx , :
	mrs	r1, cpsr
	cps	#CPSR_MODE_MON
	mov	r0, sp
	msr	cpsr, r1

	/*
	 * As we're in secure mode mon_sp points just beyond sm_ctx.sec
	 * which is sm_ctx.nsec
	 */
	bx	lr
END_FUNC sm_get_nsec_ctx
