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
#if defined(CFG_SYSCALL_WRAPPERS_MCOUNT) && !defined(__LDELF__)
	.if \scn != TEE_SCN_RETURN
	stp	x29, x30, [sp, #-80]!
	mov	x29, sp
	stp	x0, x1, [sp, #16]
	stp	x2, x3, [sp, #32]
	stp	x4, x5, [sp, #48]
	stp	x6, x7, [sp, #64]
	mov	x0, x30
	bl	_mcount
	ldp	x0, x1, [sp, #16]
	ldp	x2, x3, [sp, #32]
	ldp	x4, x5, [sp, #48]
	ldp	x6, x7, [sp, #64]
	ldp	x29, x30, [sp], #80
	.endif
#endif
        mov     x8, #(\scn)
        svc #0
        ret
        END_FUNC \name
        .endm

	FUNC _utee_panic, :
	stp	x29, x30, [sp, #-16]!
	mov	x1, sp
	bl	__utee_panic
	/* Not reached */
	END_FUNC _utee_panic

#include "utee_syscalls_asm.S"

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
