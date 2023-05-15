/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <asm.S>

	.section .text

	.macro LDELF_SYSCALL name, scn, num_args
	FUNC \name , :

	.if \num_args > 8
	.error "Too many arguments for syscall"
	.endif

	mov	x8, #(\scn)
	svc	#0
	ret
	END_FUNC \name
	.endm

	FUNC _ldelf_panic, :
	stp	x29, x30, [sp, #-16]!
	mov	x1, sp
	bl	__ldelf_panic
	/* Not reached */
	END_FUNC _ldelf_panic

#include "syscalls_asm.S"

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
