/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023 Andes Technology Corporation
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
	/* The stack pointer is always kept 16-byte aligned */
	add	sp, sp, -16
	/* Save return address and frame pointer to stack */
#if defined(RV32)
	sw	s0, 8(sp)
	sw	ra, 12(sp)
#elif defined(RV64)
	sd	s0, 0(sp)
	sd	ra, 8(sp)
#endif
	/* Assign a1 as stack pointer for scall_save_panic_stack() */
	mv	a1, sp
	/* Use tail call here because we will not return from it */
	tail	__utee_panic
	/* Not reached */
	END_FUNC _utee_panic

#include <utee_syscalls_asm.S>
