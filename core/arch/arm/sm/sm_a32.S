/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2020, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <arm32_macros.S>
#include <arm.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <sm/optee_smc.h>
#include <sm/sm.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>
#include <util.h>

#define SM_CTX_SEC_END	(SM_CTX_SEC + SM_CTX_SEC_SIZE)

	.macro save_regs mode
	cps	\mode
	mrs	r2, spsr
	str	r2, [r0], #4
	str	sp, [r0], #4
	str	lr, [r0], #4
	.endm

FUNC sm_save_unbanked_regs , :
UNWIND(	.cantunwind)
	/* User mode registers has to be saved from system mode */
	cps	#CPSR_MODE_SYS
	str	sp, [r0], #4
	str	lr, [r0], #4

	save_regs	#CPSR_MODE_IRQ
	save_regs	#CPSR_MODE_FIQ
	save_regs	#CPSR_MODE_SVC
	save_regs	#CPSR_MODE_ABT
	save_regs	#CPSR_MODE_UND

#ifdef CFG_SM_NO_CYCLE_COUNTING
	read_pmcr r2
	stm	r0!, {r2}
#endif

#ifdef CFG_FTRACE_SUPPORT
	read_cntkctl r2
	stm	r0!, {r2}
#endif
	cps	#CPSR_MODE_MON
	bx	lr
END_FUNC sm_save_unbanked_regs

	.macro restore_regs mode
	cps	\mode
	ldr	r2, [r0], #4
	ldr	sp, [r0], #4
	ldr	lr, [r0], #4
	msr	spsr_fsxc, r2
	.endm

/* Restores the mode specific registers */
FUNC sm_restore_unbanked_regs , :
UNWIND(	.cantunwind)
	/* User mode registers has to be saved from system mode */
	cps	#CPSR_MODE_SYS
	ldr	sp, [r0], #4
	ldr	lr, [r0], #4

	restore_regs	#CPSR_MODE_IRQ
	restore_regs	#CPSR_MODE_FIQ
	restore_regs	#CPSR_MODE_SVC
	restore_regs	#CPSR_MODE_ABT
	restore_regs	#CPSR_MODE_UND

#ifdef CFG_SM_NO_CYCLE_COUNTING
	ldm	r0!, {r2}
	write_pmcr r2
#endif

#ifdef CFG_FTRACE_SUPPORT
	ldm	r0!, {r2}
	write_cntkctl r2
#endif
	cps	#CPSR_MODE_MON
	bx	lr
END_FUNC sm_restore_unbanked_regs

/*
 * stack_tmp is used as stack, the top of the stack is reserved to hold
 * struct sm_ctx, everything below is for normal stack usage. As several
 * different CPU modes are using the same stack it's important that switch
 * of CPU mode isn't done until one mode is done. This means FIQ, IRQ and
 * Async abort has to be masked while using stack_tmp.
 */
LOCAL_FUNC sm_smc_entry , :
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
	bl	sm_save_unbanked_regs

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
	bl	sm_restore_unbanked_regs

.sm_ret_to_nsec:
	/*
	 * Return to non-secure world
	 */
	add     r0, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R8)
	ldm	r0, {r8-r12}

#ifdef CFG_CORE_WORKAROUND_NSITR_CACHE_PRIME
	/*
	 * Prevent leaking information about which code has been executed.
	 * This is required to be used together with
	 * CFG_CORE_WORKAROUND_SPECTRE_BP to protect Cortex A15 CPUs too.
	 *
	 * CFG_CORE_WORKAROUND_SPECTRE_BP also invalidates the branch
	 * predictor on affected CPUs. In the cases where an alternative
	 * vector has been installed the branch predictor is already
	 * invalidated so invalidating here again would be redundant, but
	 * testing for that is more trouble than it's worth.
	 */
	write_bpiall
#endif

	/* Update SCR */
	read_scr r0
	orr	r0, r0, #(SCR_NS | SCR_FIQ) /* Set NS and FIQ bit in SCR */
	write_scr r0
	/*
	 * isb not needed since we're doing an exception return below
	 * without dependency to the changes in SCR before that.
	 */

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
	isb

	add	r0, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R8)
	stm	r0, {r8-r12}

	mov	r0, sp
	bl	sm_from_nsec
	cmp	r0, #SM_EXIT_TO_NON_SECURE
	beq	.sm_ret_to_nsec

	/*
	 * Continue into secure world
	 */
	add	sp, sp, #(SM_CTX_SEC + SM_SEC_CTX_R0)

.sm_exit:
	pop	{r0-r7}
	rfefd	sp!
END_FUNC sm_smc_entry

/*
 * FIQ handling
 *
 * Saves CPU context in the same way as sm_smc_entry() above. The CPU
 * context will later be restored by sm_smc_entry() when handling a return
 * from FIQ.
 */
LOCAL_FUNC sm_fiq_entry , :
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
	isb

	/* Save non-secure context */
	add	r0, sp, #SM_CTX_NSEC
	bl	sm_save_unbanked_regs
	add     r0, sp, #(SM_CTX_NSEC + SM_NSEC_CTX_R8)
	stm	r0!, {r8-r12}

	/* Set FIQ entry */
	ldr	r0, =vector_fiq_entry
	str	r0, [sp, #(SM_CTX_SEC + SM_SEC_CTX_MON_LR)]

	/* Restore secure context */
	add	r0, sp, #SM_CTX_SEC
	bl	sm_restore_unbanked_regs

	add	sp, sp, #(SM_CTX_SEC + SM_SEC_CTX_MON_LR)

	rfefd	sp!
END_FUNC sm_fiq_entry

LOCAL_FUNC sm_vect_table , :, align=32
UNWIND(	.cantunwind)
	b	.		/* Reset			*/
	b	.		/* Undefined instruction	*/
	b	sm_smc_entry	/* Secure monitor call		*/
	b	.		/* Prefetch abort		*/
	b	.		/* Data abort			*/
	b	.		/* Reserved			*/
	b	.		/* IRQ				*/
	b	sm_fiq_entry	/* FIQ				*/
END_FUNC sm_vect_table

#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP
	.macro vector_prologue_spectre
		/*
		 * This depends on SP being 8 byte aligned, that is, the
		 * lowest three bits in SP are zero.
		 *
		 * The idea is to form a specific bit pattern in the lowest
		 * three bits of SP depending on which entry in the vector
		 * we enter via.  This is done by adding 1 to SP in each
		 * entry but the last.
		 */
		add	sp, sp, #1	/* 7:111 Reset			*/
		add	sp, sp, #1	/* 6:110 Undefined instruction	*/
		add	sp, sp, #1	/* 5:101 Secure monitor call	*/
		add	sp, sp, #1	/* 4:100 Prefetch abort		*/
		add	sp, sp, #1	/* 3:011 Data abort		*/
		add	sp, sp, #1	/* 2:010 Reserved		*/
		add	sp, sp, #1	/* 1:001 IRQ			*/
		nop			/* 0:000 FIQ			*/
	.endm

LOCAL_FUNC sm_vect_table_a15 , :, align=32
UNWIND(	.cantunwind)
	vector_prologue_spectre
	/*
	 * Invalidate the branch predictor for the current processor.
	 * For Cortex-A8 ACTLR[6] has to be set to 1 for BPIALL to be
	 * effective.
	 * Note that the BPIALL instruction is not effective in
	 * invalidating the branch predictor on Cortex-A15. For that CPU,
	 * set ACTLR[0] to 1 during early processor initialisation, and
	 * invalidate the branch predictor by performing an ICIALLU
	 * instruction. See also:
	 * https://github.com/ARM-software/arm-trusted-firmware/wiki/Arm-Trusted-Firmware-Security-Advisory-TFV-6#variant-2-cve-2017-5715
	 */
	write_iciallu
	isb
	b	1f
END_FUNC sm_vect_table_a15


LOCAL_FUNC sm_vect_table_bpiall , :, align=32
UNWIND(	.cantunwind)
	vector_prologue_spectre
	/* Invalidate the branch predictor for the current processor. */
	write_bpiall
	isb

1:
	/*
	 * Only two exception does normally occur, smc and fiq. With all
	 * other exceptions it's good enough to just spinn, the lowest bits
	 * still tells which exception we're stuck with when attaching a
	 * debugger.
	 */

	/* Test for FIQ, all the lowest bits of SP are supposed to be 0 */
	tst	sp, #(BIT(0) | BIT(1) | BIT(2))
	beq	sm_fiq_entry

	/* Test for SMC, xor the lowest bits of SP to be 0 */
	eor	sp, sp, #(BIT(0) | BIT(2))
	tst	sp, #(BIT(0) | BIT(1) | BIT(2))
	beq	sm_smc_entry

	/* unhandled exception */
	b	.
END_FUNC sm_vect_table_bpiall
#endif /*!CFG_CORE_WORKAROUND_SPECTRE_BP*/

/* void sm_init(vaddr_t stack_pointer); */
FUNC sm_init , :
	/* Set monitor stack */
	mrs	r1, cpsr
	cps	#CPSR_MODE_MON
	/* Point just beyond sm_ctx.sec */
	sub	sp, r0, #(SM_CTX_SIZE - SM_CTX_SEC_END)

#ifdef CFG_INIT_CNTVOFF
	read_scr r0
	orr	r0, r0, #SCR_NS /* Set NS bit in SCR */
	write_scr r0
	isb

	/*
	 * Accessing CNTVOFF:
	 * If the implementation includes the Virtualization Extensions
	 * this is a RW register, accessible from Hyp mode, and
	 * from Monitor mode when SCR.NS is set to 1.
	 * If the implementation includes the Security Extensions
	 * but not the Virtualization Extensions, an MCRR or MRRC to
	 * the CNTVOFF encoding is UNPREDICTABLE if executed in Monitor
	 * mode, regardless of the value of SCR.NS.
	 */
	read_id_pfr1 r2
	mov	r3, r2
	ands    r3, r3, #IDPFR1_GENTIMER_MASK
	beq	.no_gentimer
	ands    r2, r2, #IDPFR1_VIRT_MASK
	beq	.no_gentimer
	mov	r2, #0
	write_cntvoff r2, r2

.no_gentimer:
	bic	r0, r0, #SCR_NS /* Clr NS bit in SCR */
	write_scr r0
	isb
#endif
#ifdef CFG_SM_NO_CYCLE_COUNTING
	read_pmcr r0
	orr	r0, #PMCR_DP
	write_pmcr r0
#endif
	msr	cpsr, r1

#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP
	/*
	 * For unrecognized CPUs we fall back to the vector used for
	 * unaffected CPUs. Cortex A-15 has special treatment compared to
	 * the other affected Cortex CPUs.
	 */
	read_midr r1
	ubfx	r2, r1, #MIDR_IMPLEMENTER_SHIFT, #MIDR_IMPLEMENTER_WIDTH
	cmp	r2, #MIDR_IMPLEMENTER_ARM
	bne	1f

	ubfx	r2, r1, #MIDR_PRIMARY_PART_NUM_SHIFT, \
			#MIDR_PRIMARY_PART_NUM_WIDTH

	movw	r3, #CORTEX_A8_PART_NUM
	cmp	r2, r3
	movwne	r3, #CORTEX_A9_PART_NUM
	cmpne	r2, r3
	movwne	r3, #CORTEX_A17_PART_NUM
	cmpne	r2, r3
	ldreq	r0, =sm_vect_table_bpiall
	beq	2f

	movw	r3, #CORTEX_A15_PART_NUM
	cmp	r2, r3
	ldreq	r0, =sm_vect_table_a15
	beq	2f
#endif
	/* Set monitor vector (MVBAR) */
1:	ldr	r0, =sm_vect_table
2:	write_mvbar r0

	bx	lr
END_FUNC sm_init
DECLARE_KEEP_PAGER sm_init


/* struct sm_nsec_ctx *sm_get_nsec_ctx(void); */
FUNC sm_get_nsec_ctx , :
	mrs	r1, cpsr
	cps	#CPSR_MODE_MON
	/*
	 * As we're in secure mode mon_sp points just beyond sm_ctx.sec,
	 * which allows us to calculate the address of sm_ctx.nsec.
	 */
	add	r0, sp, #(SM_CTX_NSEC - SM_CTX_SEC_END)
	msr	cpsr, r1

	bx	lr
END_FUNC sm_get_nsec_ctx
