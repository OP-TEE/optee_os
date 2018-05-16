/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <tee_syscall_numbers.h>
#include <asm.S>

#if defined(CFG_UNWIND)
#define UNWIND(...)	__VA_ARGS__
#else
#define UNWIND(...)
#endif

        .section .text
        .balign 4
        .code 32

        .macro UTEE_SYSCALL name, scn, num_args
	FUNC \name , :

UNWIND( .fnstart)
        push    {r5-r7,lr}
UNWIND( .save   {r5-r7,lr})
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
UNWIND( .fnend)
	END_FUNC \name
        .endm

	FUNC utee_panic, :
UNWIND( .fnstart)
	push	{r0-r11, lr}
UNWIND(	.save	{r0-r11, lr})
	mov	lr, pc
	push	{lr}
UNWIND(	.save	{lr})
	mov	r1, sp
	bl	__utee_panic
	/* Not reached */
UNWIND( .fnend)
	END_FUNC utee_panic

#include "utee_syscalls_asm.S"
