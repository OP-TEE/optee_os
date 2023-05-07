/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright  2022  Beijing ESWIN Computing Technology Co., Ltd.
 */

#include <tee_syscall_numbers.h>
#include <asm.S>

        .section .text

        .macro UTEE_SYSCALL name, scn, num_args
	FUNC \name , :

	.if \num_args > TEE_SVC_MAX_ARGS || \num_args > 8
	.error "Too many arguments for syscall"
	.endif
	li	t0, \scn
	li	t1, \num_args
	ecall
	ret
	END_FUNC \name
	.endm

	FUNC _utee_panic, :
	j	__utee_panic
	END_FUNC _utee_panic

#include <utee_syscalls_asm.S>
