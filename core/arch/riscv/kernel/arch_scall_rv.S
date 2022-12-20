/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */
#include "tee_syscall_numbers.h"
#include "trace_levels.h"
#include <asm.S>
#include <generated/asm-defines.h>
#include <kernel/thread.h>
#include <riscv.h>
#include <riscv_macros.S>
#include <tee_api_defines.h>

/*
 * uint32_t scall_do_call(struct thread_scall_regs *regs, syscall_t func);
 *
 * Called from scall_handle_user_ta()
 */
FUNC scall_do_call , :
	addi	sp, sp, -16

	/* Save scall regs to t0 */
	mv	t0, a0

	/* Save func to t1 */
	mv	t1, a1

	/* Push return address to stack */
	store_xregs sp, 0, 1

	/* Load arguments to function */
	load_xregs a0, THREAD_SCALL_REG_A0, 10, 17

	/* Call the syscall function */
	jalr	t1

	/* Pop return address from stack */
	load_xregs	sp, 0, 1

	addi	sp, sp, 16
	ret
END_FUNC scall_do_call

/*
 * void syscall_sys_return(uint32_t ret);
 */
FUNC syscall_sys_return , :
	li	a1, 0  /* panic = false */
	li	a2, 0  /* panic_code = 0 */
	mv	a3, t0 /* pointer to struct thread_scall_regs */
	j	scall_sys_return_helper
END_FUNC syscall_sys_return

/*
 * void syscall_panic(uint32_t code);
 */
FUNC syscall_panic , :
	li	a1, 1  /* panic = true */
	mv	a2, a0  /* code */
	li	a0, TEE_ERROR_TARGET_DEAD
	mv	a3, t0 /* pointer to struct thread_scall_regs */
	j	scall_sys_return_helper
END_FUNC syscall_panic
