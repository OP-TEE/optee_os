/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <tee_syscall_numbers.h>
#include <asm.S>

        .section .text

        .macro UTEE_SYSCALL name, scn, num_args
	FUNC \name , :

	.if \num_args > TEE_SVC_MAX_ARGS || \num_args > 8
	.error "Too many arguments for syscall"
	.endif
        mov     x8, #(\scn)
        svc #0
        ret
        END_FUNC \name
        .endm

	FUNC utee_panic, :
	stp	x29, x30, [sp, #-16]!
	mov	x1, sp
	bl	__utee_panic
	/* Not reached */
	END_FUNC utee_panic

#include "utee_syscalls_asm.S"

