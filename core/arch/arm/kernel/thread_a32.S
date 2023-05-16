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
#include <kernel/abort.h>
#include <kernel/cache_helpers.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <mm/core_mmu.h>

	.syntax unified
	.arch_extension sec

	.macro cmp_spsr_user_mode reg:req
		/*
		 * We're only testing the lower 4 bits as bit 5 (0x10)
		 * always is set.
		 */
		tst	\reg, #0x0f
	.endm

FUNC thread_set_abt_sp , :
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_ABT
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_abt_sp

FUNC thread_set_und_sp , :
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_UND
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_und_sp

FUNC thread_set_irq_sp , :
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_IRQ
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_irq_sp

FUNC thread_set_fiq_sp , :
UNWIND(	.cantunwind)
	mrs	r1, cpsr
	cps	#CPSR_MODE_FIQ
	mov	sp, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_fiq_sp

FUNC thread_get_usr_sp , :
	mrs	r1, cpsr
	cpsid	aif
	cps	#CPSR_MODE_SYS
	mov	r0, sp
	msr	cpsr, r1
	bx	lr
END_FUNC thread_get_usr_sp

FUNC thread_get_usr_lr , :
	mrs	r1, cpsr
	cpsid	aif
	cps	#CPSR_MODE_SYS
	mov	r0, lr
	msr	cpsr, r1
	bx	lr
END_FUNC thread_get_usr_lr

FUNC thread_set_usr_lr , :
	mrs	r1, cpsr
	cpsid	aif
	cps	#CPSR_MODE_SYS
	mov	lr, r0
	msr	cpsr, r1
	bx	lr
END_FUNC thread_set_usr_lr

/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
UNWIND(	.cantunwind)
	add	r12, r0, #(13 * 4)	/* Restore registers r0-r12 later */

	cps	#CPSR_MODE_SYS
	ldr	sp, [r12], #4
	ldr	lr, [r12], #4

	cps	#CPSR_MODE_SVC
	ldr	r1, [r12], #4
	ldr	sp, [r12], #4
	ldr	lr, [r12], #4
	msr	spsr_fsxc, r1

	ldm	r12, {r1, r2}

	/*
	 * Switching to some other mode than SVC as we need to set spsr in
	 * order to return into the old state properly and it may be SVC
	 * mode we're returning to.
	 */
	cps	#CPSR_MODE_ABT
	cmp_spsr_user_mode r2
	mov	lr, r1
	msr	spsr_fsxc, r2
	ldm	r0, {r0-r12}
	movsne	pc, lr
	b	eret_to_user_mode
END_FUNC thread_resume

/*
 * Disables IRQ and FIQ and saves state of thread in fiq mode which has
 * the banked r8-r12 registers, returns original CPSR.
 */
LOCAL_FUNC thread_save_state_fiq , :
UNWIND(	.cantunwind)
	mov	r9, lr

	/*
	 * Uses stack for temporary storage, while storing needed
	 * context in the thread context struct.
	 */

	mrs	r8, cpsr

	cpsid	aif			/* Disable Async abort, IRQ and FIQ */

	push	{r4-r7}
	push	{r0-r3}

	mrs	r6, cpsr		/* Save current CPSR */

	bl	thread_get_ctx_regs

	pop	{r1-r4}			/* r0-r3 pushed above */
	stm	r0!, {r1-r4}
	pop	{r1-r4}			/* r4-r7 pushed above */
	stm	r0!, {r1-r4}

	cps     #CPSR_MODE_SYS
	stm	r0!, {r8-r12}
	str	sp, [r0], #4
	str	lr, [r0], #4

	cps     #CPSR_MODE_SVC
	mrs     r1, spsr
	str	r1, [r0], #4
	str	sp, [r0], #4
	str	lr, [r0], #4

	/* back to fiq mode */
	orr	r6, r6, #ARM32_CPSR_FIA	/* Disable Async abort, IRQ and FIQ */
	msr	cpsr, r6		/* Restore mode */

	mov	r0, r8			/* Return original CPSR */
	bx	r9
END_FUNC thread_save_state_fiq

/*
 * Disables IRQ and FIQ and saves state of thread, returns original
 * CPSR.
 */
FUNC thread_save_state , :
UNWIND(	.cantunwind)
	push	{r12, lr}
	/*
	 * Uses stack for temporary storage, while storing needed
	 * context in the thread context struct.
	 */

	mrs	r12, cpsr

	cpsid	aif			/* Disable Async abort, IRQ and FIQ */

	push	{r4-r7}
	push	{r0-r3}

	mov	r5, r12			/* Save CPSR in a preserved register */
	mrs	r6, cpsr		/* Save current CPSR */

	bl	thread_get_ctx_regs

	pop	{r1-r4}			/* r0-r3 pushed above */
	stm	r0!, {r1-r4}
	pop	{r1-r4}			/* r4-r7 pushed above */
	stm	r0!, {r1-r4}
	stm	r0!, {r8-r11}

	pop	{r12, lr}
	stm	r0!, {r12}

        cps     #CPSR_MODE_SYS
	str	sp, [r0], #4
	str	lr, [r0], #4

        cps     #CPSR_MODE_SVC
        mrs     r1, spsr
	str	r1, [r0], #4
	str	sp, [r0], #4
	str	lr, [r0], #4

	orr	r6, r6, #ARM32_CPSR_FIA	/* Disable Async abort, IRQ and FIQ */
	msr	cpsr, r6		/* Restore mode */

	mov	r0, r5			/* Return original CPSR */
	bx	lr
END_FUNC thread_save_state

#ifdef CFG_CORE_SEL2_SPMC
/*
 * unsigned long thread_hvc(unsigned long func_id, unsigned long a1,
 *			    unsigned long a2, unsigned long a3)
 */
FUNC thread_hvc , :
	push	{r4-r7}
UNWIND(	.save	{r4-r7})
	hvc	#0
	pop	{r4-r7}
	bx	lr
END_FUNC thread_hvc
#endif /*CFG_CORE_SEL2_SPMC*/

/*
 * unsigned long thread_smc(unsigned long func_id, unsigned long a1,
 *			    unsigned long a2, unsigned long a3)
 */
FUNC thread_smc , :
	push	{r4-r7}
UNWIND(	.save	{r4-r7})
	smc	#0
	pop	{r4-r7}
	bx	lr
END_FUNC thread_smc

/* void thread_smccc(struct thread_smc_args *arg_res) */
FUNC thread_smccc , :
	push	{r4-r7}
	push	{r0, lr}
	ldm	r0, {r0-r7}
#ifdef CFG_CORE_SEL2_SPMC
	hvc	#0
#else
	smc	#0
#endif
	pop	{r12, lr}
	stm	r12, {r0-r7}
	pop	{r4-r7}
	bx	lr
END_FUNC thread_smccc

FUNC thread_init_vbar , :
	/* Set vector (VBAR) */
	write_vbar r0
	bx	lr
END_FUNC thread_init_vbar
DECLARE_KEEP_PAGER thread_init_vbar

/*
 * Below are low level routines handling entry and return from user mode.
 *
 * thread_enter_user_mode() saves all that registers user mode can change
 * so kernel mode can restore needed registers when resuming execution
 * after the call to thread_enter_user_mode() has returned.
 * thread_enter_user_mode() doesn't return directly since it enters user
 * mode instead, it's thread_unwind_user_mode() that does the
 * returning by restoring the registers saved by thread_enter_user_mode().
 *
 * There's three ways for thread_enter_user_mode() to return to caller,
 * user TA calls _utee_return, user TA calls _utee_panic or through an abort.
 *
 * Calls to _utee_return or _utee_panic are handled as:
 * __thread_svc_handler() -> thread_scall_handler() -> scall_do_call() which
 * calls syscall_return() or syscall_panic().
 *
 * These function calls returns normally except thread_scall_handler() which
 * which is an exception handling routine so it reads return address and
 * SPSR to restore from the stack. syscall_return() and syscall_panic()
 * changes return address and SPSR used by thread_scall_handler() to instead of
 * returning into user mode as with other syscalls it returns into
 * thread_unwind_user_mode() in kernel mode instead.  When
 * thread_scall_handler() returns the stack pointer at the point where
 * thread_enter_user_mode() left it so this is where
 * thread_unwind_user_mode() can operate.
 *
 * Aborts are handled in a similar way but by thread_abort_handler()
 * instead, when the pager sees that it's an abort from user mode that
 * can't be handled it updates SPSR and return address used by
 * thread_abort_handler() to return into thread_unwind_user_mode()
 * instead.
 */

/*
 * uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
 *				     uint32_t *exit_status0,
 *				     uint32_t *exit_status1);
 *
 * This function depends on being called with exceptions masked.
 */
FUNC __thread_enter_user_mode , :
UNWIND(	.cantunwind)
	/*
	 * Save all registers to allow syscall_return() to resume execution
	 * as if this function would have returned. This is also used in
	 * syscall_panic().
	 *
	 * If stack usage of this function is changed
	 * thread_unwind_user_mode() has to be updated.
	 */
	push    {r4-r12,lr}

	/*
	 * Save old user sp and set new user sp.
	 */
	cps	#CPSR_MODE_SYS
	mov	r4, sp
	ldr	sp, [r0, #THREAD_CTX_REGS_USR_SP]
	cps	#CPSR_MODE_SVC

	push	{r1, r2, r4, r5}

	/* Prepare user mode entry via eret_to_user_mode */
	ldr	lr, [r0, #THREAD_CTX_REGS_PC]
	ldr	r4, [r0, #THREAD_CTX_REGS_CPSR]
	msr     spsr_fsxc, r4

	ldm	r0, {r0-r12}

	b	eret_to_user_mode
END_FUNC __thread_enter_user_mode

/*
 * void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
 *              uint32_t exit_status1);
 * See description in thread.h
 */
FUNC thread_unwind_user_mode , :
UNWIND(	.cantunwind)
	/* Match push {r1, r2, r4, r5} in thread_enter_user_mode() */
	pop	{r4-r7}
	str	r1, [r4]
	str	r2, [r5]

	/* Restore old user sp */
	cps	#CPSR_MODE_SYS
	mov	sp, r6
	cps	#CPSR_MODE_SVC

	/* Match push {r4-r12,lr} in thread_enter_user_mode() */
	pop     {r4-r12,pc}
END_FUNC thread_unwind_user_mode

	.macro maybe_restore_mapping
		/*
		 * This macro is a bit hard to read due to all the ifdefs,
		 * we're testing for two different configs which makes four
		 * different combinations.
		 *
		 * - With LPAE, and then some extra code if with
		 *   CFG_CORE_UNMAP_CORE_AT_EL0
		 * - Without LPAE, and then some extra code if with
		 *   CFG_CORE_UNMAP_CORE_AT_EL0
		 */

		/*
		 * At this point we can't rely on any memory being writable
		 * yet, so we're using TPIDRPRW to store r0, and if with
		 * LPAE TPIDRURO to store r1 too.
		 */
		write_tpidrprw r0
#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) || defined(CFG_WITH_LPAE)
		write_tpidruro r1
#endif

#ifdef CFG_WITH_LPAE
		read_ttbr0_64bit r0, r1
		tst	r1, #BIT(TTBR_ASID_SHIFT - 32)
		beq	11f

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
		/*
		 * Update the mapping to use the full kernel mode mapping.
		 * Since the translation table could reside above 4GB we'll
		 * have to use 64-bit arithmetics.
		 */
		subs	r0, r0, #CORE_MMU_BASE_TABLE_OFFSET
		sbc	r1, r1, #0
#endif
		bic	r1, r1, #BIT(TTBR_ASID_SHIFT - 32)
		write_ttbr0_64bit r0, r1
		isb

#else /*!CFG_WITH_LPAE*/
		read_contextidr r0
		tst	r0, #1
		beq	11f

		/* Update the mapping to use the full kernel mode mapping. */
		bic	r0, r0, #1
		write_contextidr r0
		isb
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
		read_ttbcr r0
		bic	r0, r0, #TTBCR_PD1
		write_ttbcr r0
		isb
#endif

#endif /*!CFG_WITH_LPAE*/

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
		ldr	r0, =thread_user_kcode_offset
		ldr	r0, [r0]
		read_vbar r1
		add	r1, r1, r0
		write_vbar r1
		isb

	11:	/*
		 * The PC is adjusted unconditionally to guard against the
		 * case there was an FIQ just before we did the "cpsid aif".
		 */
		ldr	r0, =22f
		bx	r0
	22:
#else
	11:
#endif
		read_tpidrprw r0
#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) || defined(CFG_WITH_LPAE)
		read_tpidruro r1
#endif
	.endm

/* The handler of native interrupt. */
.macro	native_intr_handler mode:req
	cpsid	aif
	maybe_restore_mapping

	/*
	 * FIQ and IRQ have a +4 offset for lr compared to preferred return
	 * address
	 */
	sub     lr, lr, #4

	/*
	 * We're always saving {r0-r3}. In IRQ mode we're saving r12 also.
	 * In FIQ mode we're saving the banked fiq registers {r8-r12} FIQ
	 * because the secure monitor doesn't save those. The treatment of
	 * the banked fiq registers is somewhat analogous to the lazy save
	 * of VFP registers.
	 */
	.ifc	\mode\(),fiq
	push	{r0-r3, r8-r12, lr}
	.else
	push	{r0-r3, r12, lr}
	.endif

	bl	thread_check_canaries
	bl	interrupt_main_handler

	mrs	r0, spsr
	cmp_spsr_user_mode r0

	.ifc	\mode\(),fiq
	pop	{r0-r3, r8-r12, lr}
	.else
	pop	{r0-r3, r12, lr}
	.endif

	movsne	pc, lr
	b	eret_to_user_mode
.endm

/* The handler of foreign interrupt. */
.macro foreign_intr_handler mode:req
	cpsid	aif
	maybe_restore_mapping

	sub	lr, lr, #4
	push	{r12}

	.ifc	\mode\(),fiq
	/*
	 * If a foreign (non-secure) interrupt is received as a FIQ we need
	 * to check that we're in a saveable state or if we need to mask
	 * the interrupt to be handled later.
	 *
	 * The window when this is needed is quite narrow, it's between
	 * entering the exception vector and until the "cpsid" instruction
	 * of the handler has been executed.
	 *
	 * Currently we can save the state properly if the FIQ is received
	 * while in user or svc (kernel) mode.
	 *
	 * If we're returning to abort, undef or irq mode we're returning
	 * with the mapping restored. This is OK since before the handler
	 * we're returning to eventually returns to user mode the reduced
	 * mapping will be restored.
	 */
	mrs	r12, spsr
	and	r12, r12, #ARM32_CPSR_MODE_MASK
	cmp	r12, #ARM32_CPSR_MODE_USR
	cmpne	r12, #ARM32_CPSR_MODE_SVC
	beq	1f
	mrs	r12, spsr
	orr	r12, r12, #ARM32_CPSR_F
	msr	spsr_fsxc, r12
	pop	{r12}
	movs	pc, lr
1:
	.endif

	push	{lr}

	.ifc	\mode\(),fiq
	bl	thread_save_state_fiq
	.else
	bl	thread_save_state
	.endif

#ifdef CFG_CORE_WORKAROUND_NSITR_CACHE_PRIME
	/*
	 * Prevent leaking information about which entries has been used in
	 * cache. We're relying on the secure monitor/dispatcher to take
	 * care of the BTB.
	 */
	mov	r0, #DCACHE_OP_CLEAN_INV
	bl	dcache_op_louis
	write_iciallu
#endif

	/*
	 * Use SP_abt to update core local flags.
	 * flags = (flags << THREAD_CLF_SAVED_SHIFT) | THREAD_CLF_TMP;
	 */
	cps     #CPSR_MODE_ABT
	ldr     r1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsl     r1, r1, #THREAD_CLF_SAVED_SHIFT
	orr     r1, r1, #THREAD_CLF_TMP
	str     r1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	.ifc    \mode\(),fiq
	cps     #CPSR_MODE_FIQ
	.else
	cps     #CPSR_MODE_IRQ
	.endif

	mov	r0, #THREAD_FLAGS_EXIT_ON_FOREIGN_INTR
	mrs	r1, spsr
	pop	{r2}
	pop	{r12}
	blx	thread_state_suspend

	/*
	 * Switch to SVC mode and copy current stack pointer as it already
	 * is the tmp stack.
	 */
	mov	r1, sp
	cps	#CPSR_MODE_SVC
	mov	sp, r1

	/* Passing thread index in r0 */
	b	thread_foreign_intr_exit
.endm

FUNC thread_excp_vect , :, align=32
UNWIND(	.cantunwind)
	b	.			/* Reset			*/
	b	__thread_und_handler	/* Undefined instruction	*/
	b	__thread_svc_handler	/* System call			*/
	b	__thread_pabort_handler	/* Prefetch abort		*/
	b	__thread_dabort_handler	/* Data abort			*/
	b	.			/* Reserved			*/
	b	__thread_irq_handler	/* IRQ				*/
	b	__thread_fiq_handler	/* FIQ				*/
#ifdef CFG_CORE_WORKAROUND_SPECTRE_BP_SEC
	.macro vector_prologue_spectre
		/*
		 * This depends on SP being 8 byte aligned, that is, the
		 * lowest three bits in SP are zero.
		 *
		 * To avoid unexpected speculation we need to invalidate
		 * the branch predictor before we do the first branch. It
		 * doesn't matter if it's a conditional or an unconditional
		 * branch speculation can still occur.
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
		cpsid   aif		/* 0:000 FIQ			*/
	.endm

        .balign	32
	.global thread_excp_vect_wa_a15_spectre_v2
thread_excp_vect_wa_a15_spectre_v2:
	vector_prologue_spectre
	write_tpidrprw r0
	mrs	r0, spsr
	cmp_spsr_user_mode r0
	bne	1f
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

        .balign	32
	.global thread_excp_vect_wa_spectre_v2
thread_excp_vect_wa_spectre_v2:
	vector_prologue_spectre
	write_tpidrprw r0
	mrs	r0, spsr
	cmp_spsr_user_mode r0
	bne	1f
	/* Invalidate the branch predictor for the current processor. */
	write_bpiall
	isb

1:	and	r0, sp, #(BIT(0) | BIT(1) | BIT(2))
	bic	sp, sp, #(BIT(0) | BIT(1) | BIT(2))
	add	pc, pc, r0, LSL #3
	nop

	read_tpidrprw r0
	b	__thread_fiq_handler	/* FIQ				*/
	read_tpidrprw r0
	b	__thread_irq_handler	/* IRQ				*/
	read_tpidrprw r0
	b	.			/* Reserved			*/
	read_tpidrprw r0
	b	__thread_dabort_handler	/* Data abort			*/
	read_tpidrprw r0
	b	__thread_pabort_handler	/* Prefetch abort		*/
	read_tpidrprw r0
	b	__thread_svc_handler	/* System call			*/
	read_tpidrprw r0
	b	__thread_und_handler	/* Undefined instruction	*/
	read_tpidrprw r0
	b	.			/* Reset			*/
#endif /*CFG_CORE_WORKAROUND_SPECTRE_BP_SEC*/

__thread_und_handler:
	cpsid	aif
	maybe_restore_mapping
	strd	r0, r1, [sp, #THREAD_CORE_LOCAL_R0]
	mrs	r1, spsr
	tst	r1, #CPSR_T
	subne	lr, lr, #2
	subeq	lr, lr, #4
	mov	r0, #ABORT_TYPE_UNDEF
	b	__thread_abort_common

__thread_dabort_handler:
	cpsid	aif
	maybe_restore_mapping
	strd	r0, r1, [sp, #THREAD_CORE_LOCAL_R0]
	sub	lr, lr, #8
	mov	r0, #ABORT_TYPE_DATA
	b	__thread_abort_common

__thread_pabort_handler:
	cpsid	aif
	maybe_restore_mapping
	strd	r0, r1, [sp, #THREAD_CORE_LOCAL_R0]
	sub	lr, lr, #4
	mov	r0, #ABORT_TYPE_PREFETCH

__thread_abort_common:
	/*
	 * At this label:
	 * cpsr is in mode undef or abort
	 * sp is still pointing to struct thread_core_local belonging to
	 * this core.
	 * {r0, r1} are saved in struct thread_core_local pointed to by sp
	 * {r2-r11, ip} are untouched.
	 * r0 holds the first argument for abort_handler()
	 */

	/*
	 * Update core local flags.
	 * flags = (flags << THREAD_CLF_SAVED_SHIFT) | THREAD_CLF_ABORT;
	 */
	ldr	r1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsl	r1, r1, #THREAD_CLF_SAVED_SHIFT
	orr	r1, r1, #THREAD_CLF_ABORT

	/*
	 * Select stack and update flags accordingly
	 *
	 * Normal case:
	 * If the abort stack is unused select that.
	 *
	 * Fatal error handling:
	 * If we're already using the abort stack as noted by bit
	 * (THREAD_CLF_SAVED_SHIFT + THREAD_CLF_ABORT_SHIFT) in the flags
	 * field we're selecting the temporary stack instead to be able to
	 * make a stack trace of the abort in abort mode.
	 *
	 * r1 is initialized as a temporary stack pointer until we've
	 * switched to system mode.
	 */
	tst	r1, #(THREAD_CLF_ABORT << THREAD_CLF_SAVED_SHIFT)
	orrne	r1, r1, #THREAD_CLF_TMP /* flags |= THREAD_CLF_TMP; */
	str	r1, [sp, #THREAD_CORE_LOCAL_FLAGS]
	ldrne	r1, [sp, #THREAD_CORE_LOCAL_TMP_STACK_VA_END]
	ldreq	r1, [sp, #THREAD_CORE_LOCAL_ABT_STACK_VA_END]

	/*
	 * Store registers on stack fitting struct thread_abort_regs
	 * start from the end of the struct
	 * {r2-r11, ip}
	 * Load content of previously saved {r0-r1} and stores
	 * it up to the pad field.
	 * After this is only {usr_sp, usr_lr} missing in the struct
	 */
	stmdb	r1!, {r2-r11, ip}	/* Push on the selected stack */
	ldrd	r2, r3, [sp, #THREAD_CORE_LOCAL_R0]
	/* Push the original {r0-r1} on the selected stack */
	stmdb	r1!, {r2-r3}
	mrs	r3, spsr
	/* Push {pad, spsr, elr} on the selected stack */
	stmdb	r1!, {r2, r3, lr}

	cps	#CPSR_MODE_SYS
	str	lr, [r1, #-4]!
	str	sp, [r1, #-4]!
	mov	sp, r1

	bl	abort_handler

	mov	ip, sp
	ldr	sp, [ip], #4
	ldr	lr, [ip], #4

	/*
	 * Even if we entered via CPSR_MODE_UND, we are returning via
	 * CPSR_MODE_ABT. It doesn't matter as lr and spsr are assigned
	 * here.
	 */
	cps	#CPSR_MODE_ABT
	ldm	ip!, {r0, r1, lr}	/* r0 is pad */
	msr	spsr_fsxc, r1

	/* Update core local flags */
	ldr	r0, [sp, #THREAD_CORE_LOCAL_FLAGS]
	lsr	r0, r0, #THREAD_CLF_SAVED_SHIFT
	str	r0, [sp, #THREAD_CORE_LOCAL_FLAGS]

	cmp_spsr_user_mode r1
	ldm	ip, {r0-r11, ip}
	movsne	pc, lr
	b	eret_to_user_mode
	/* end thread_abort_common */

__thread_svc_handler:
	cpsid	aif

	maybe_restore_mapping

	push	{r0-r7, lr}
	mrs	r0, spsr
	push	{r0}
	mov	r0, sp
	bl	thread_scall_handler
	cpsid	aif	/* In case something was unmasked */
	pop	{r0}
	msr	spsr_fsxc, r0
	cmp_spsr_user_mode r0
	pop	{r0-r7, lr}
	movsne	pc, lr
	b	eret_to_user_mode
	/* end thread_svc_handler */

__thread_fiq_handler:
#if defined(CFG_CORE_IRQ_IS_NATIVE_INTR)
	foreign_intr_handler	fiq
#else
	native_intr_handler	fiq
#endif
	/* end thread_fiq_handler */

__thread_irq_handler:
#if defined(CFG_CORE_IRQ_IS_NATIVE_INTR)
	native_intr_handler	irq
#else
	foreign_intr_handler	irq
#endif
	/* end thread_irq_handler */

	/*
	 * Returns to user mode.
	 * Expects to be jumped to with lr pointing to the user space
	 * address to jump to and spsr holding the desired cpsr. Async
	 * abort, irq and fiq should be masked.
	 */
eret_to_user_mode:
	write_tpidrprw r0
#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) || defined(CFG_WITH_LPAE)
	write_tpidruro r1
#endif

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	ldr	r0, =thread_user_kcode_offset
	ldr	r0, [r0]
	read_vbar r1
	sub	r1, r1, r0
	write_vbar r1
	isb

	/* Jump into the reduced mapping before the full mapping is removed */
	ldr	r1, =1f
	sub	r1, r1, r0
	bx	r1
1:
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/

#ifdef CFG_WITH_LPAE
	read_ttbr0_64bit r0, r1
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	add	r0, r0, #CORE_MMU_BASE_TABLE_OFFSET
#endif
	/* switch to user ASID */
	orr	r1, r1, #BIT(TTBR_ASID_SHIFT - 32)
	write_ttbr0_64bit r0, r1
	isb
#else /*!CFG_WITH_LPAE*/
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	read_ttbcr r0
	orr	r0, r0, #TTBCR_PD1
	write_ttbcr r0
	isb
#endif
	read_contextidr r0
	orr	r0, r0, #BIT(0)
	write_contextidr r0
	isb
#endif /*!CFG_WITH_LPAE*/

	read_tpidrprw r0
#if defined(CFG_CORE_UNMAP_CORE_AT_EL0) || defined(CFG_WITH_LPAE)
	read_tpidruro r1
#endif

	movs	pc, lr

	/*
	 * void icache_inv_user_range(void *addr, size_t size);
	 *
	 * This function has to execute with the user space ASID active,
	 * this means executing with reduced mapping and the code needs
	 * to be located here together with the vector.
	 */
	.global icache_inv_user_range
	.type icache_inv_user_range , %function
icache_inv_user_range:
	push	{r4-r7}

	/* Mask all exceptions */
	mrs	r4, cpsr	/* This register must be preserved */
	cpsid	aif

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	ldr	r2, =thread_user_kcode_offset
	ldr	r2, [r2]
	read_vbar r5		/* This register must be preserved */
	sub	r3, r5, r2
	write_vbar r3
	isb

	/* Jump into the reduced mapping before the full mapping is removed */
	ldr	r3, =1f
	sub	r3, r3, r2
	bx	r3
1:
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/

#ifdef CFG_WITH_LPAE
	read_ttbr0_64bit r6, r7	/* These registers must be preseved */
	/* switch to user ASID */
	orr	r3, r7, #BIT(TTBR_ASID_SHIFT - 32)
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	add	r2, r6, #CORE_MMU_BASE_TABLE_OFFSET
	write_ttbr0_64bit r2, r3
#else
	write_ttbr0_64bit r6, r3
#endif
	isb
#else /*!CFG_WITH_LPAE*/
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	read_ttbcr r6	/* This register must be preserved */
	orr	r2, r6, #TTBCR_PD1
	write_ttbcr r2
	isb
#endif /*CFG_CORE_UNMAP_CORE_AT_EL0*/
	read_contextidr r7	/* This register must be preserved */
	orr	r2, r7, #BIT(0)
	write_contextidr r2
	isb
#endif /*!CFG_WITH_LPAE*/

	/*
	 * Do the actual icache invalidation
	 */

	/* Calculate minimum icache line size, result in r2 */
	read_ctr r3
	and     r3, r3, #CTR_IMINLINE_MASK
	mov     r2, #CTR_WORD_SIZE
	lsl     r2, r2, r3

	add	r1, r0, r1
	sub	r3, r2, #1
	bic	r0, r0, r3
1:
	write_icimvau r0
	add	r0, r0, r2
	cmp	r0, r1
	blo	1b

	/* Invalidate entire branch predictor array inner shareable */
	write_bpiallis

	dsb	ishst
	isb

#ifdef CFG_WITH_LPAE
	write_ttbr0_64bit r6, r7
	isb
#else /*!CFG_WITH_LPAE*/
	write_contextidr r7
	isb
#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	write_ttbcr r6
	isb
#endif
#endif /*!CFG_WITH_LPAE*/

#ifdef CFG_CORE_UNMAP_CORE_AT_EL0
	write_vbar r5
	isb
	/*
	 * The PC is adjusted unconditionally to guard against the
	 * case there was an FIQ just before we did the "cpsid aif".
	 */
	ldr	r0, =1f
	bx	r0
1:
#endif

	msr	cpsr_fsxc, r4	/* Restore exceptions */
	pop	{r4-r7}
	bx	lr		/* End of icache_inv_user_range() */

	/*
	 * Make sure that literals are placed before the
	 * thread_excp_vect_end label.
	 */
	.pool
	.global thread_excp_vect_end
thread_excp_vect_end:
END_FUNC thread_excp_vect
