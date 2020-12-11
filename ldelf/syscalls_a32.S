/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <asm.S>

	.section .text
	.balign 4
	.code 32

	.macro LDELF_SYSCALL name, scn, num_args
	FUNC \name , :

	.if \num_args > 8
	.error "Too many arguments for syscall"
	.endif

	push	{r5-r7, lr}
UNWIND(	.save	{r5-r7, lr})
	mov	r7, #(\scn)

	.if \num_args <= 4
	@ No arguments passed on stack
	mov	r6, #0
	.else
	@ Tell number of arguments passed on the stack
	mov	r6, #(\num_args - 4)
	@ Point just before the push (4 registers) above on the first argument
	add	r5, sp, #(4 * 4)
	.endif

	svc	#0
	pop	{r5-r7, pc}
	END_FUNC \name
	.endm

	FUNC _ldelf_panic, :
	push	{r0-r11, lr}
UNWIND(	.save	{r0-r11, lr})
	mov	lr, pc
	push	{lr}
UNWIND(	.save	{lr})
	mov	r1, sp
	bl	__ldelf_panic
	/* Not reached */
	END_FUNC _ldelf_panic

#include "syscalls_asm.S"
