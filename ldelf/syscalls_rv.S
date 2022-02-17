/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#include <asm.S>

.section .text

.macro LDELF_SYSCALL name, scn, num_args
FUNC \name , :

.if \num_args > 8
.error "Too many arguments for syscall"
.endif

li	a0, \scn
ecall
END_FUNC \name
.endm

FUNC _ldelf_panic, :
j .
/* Not reached */
END_FUNC _ldelf_panic

#include "syscalls_asm.S"

