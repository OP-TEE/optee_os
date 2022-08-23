/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <tee_syscall_numbers.h>
#include <asm.S>

	.section .note.GNU-stack,"",%progbits

        .section .text
        .balign 4
        .code 32

        .macro UTEE_SYSCALL name, scn, num_args
	FUNC \name , :
        push    {r5-r7,lr}
UNWIND( .save   {r5-r7,lr})
#if defined(CFG_SYSCALL_WRAPPERS_MCOUNT) && !defined(__LDELF__)
	.if \scn != TEE_SCN_RETURN
	mov	ip, sp
	push	{r0-r4, fp, ip}
	add	fp, ip, #16
	push	{lr}
	bl	__gnu_mcount_nc
	pop	{r0-r4, fp, ip}
	mov	sp, ip
	.endif
#endif
        mov     r7, #(\scn)
	.if \num_args > TEE_SVC_MAX_ARGS
	.error "Too many arguments for syscall"
	.endif
        .if \num_args <= 4
        @ No arguments passed on stack
        mov     r6, #0
        .else
        @ Tell number of arguments passed on the stack
        mov     r6, #(\num_args - 4)
        @ Point just before the push (4 registers) above on the first argument
        add     r5, sp, #(4 * 4)
        .endif
        svc #0
        pop     {r5-r7,pc}
	END_FUNC \name
        .endm

	FUNC _utee_panic, :
	push	{r0-r11, lr}
UNWIND(	.save	{r0-r11, lr})
	mov	lr, pc
	push	{lr}
UNWIND(	.save	{lr})
	mov	r1, sp
	bl	__utee_panic
	/* Not reached */
	END_FUNC _utee_panic

#include "utee_syscalls_asm.S"
