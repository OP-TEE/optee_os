/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2022, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */
#ifndef __KERNEL_SCALL_H
#define __KERNEL_SCALL_H

#include <types_ext.h>

/*
 * Generic "pointer to function" type. Actual syscalls take zero or more
 * arguments and return TEE_Result.
 */
typedef void (*syscall_t)(void);

struct thread_scall_regs;

/* Helper function for scall_handle_user_ta() and scall_handle_ldelf() */
uint32_t scall_do_call(struct thread_scall_regs *regs, syscall_t func);

/* Registered as .handle_scall in struct tee_ta_ops for user TAs. */
bool scall_handle_user_ta(struct thread_scall_regs *regs);

/* Separate syscall handler for calls from ldelf */
bool scall_handle_ldelf(struct thread_scall_regs *regs);

/*
 * Called from the assembly functions syscall_sys_return() and
 * syscall_panic() to update the register values in the struct
 * thread_scall_regs to return back to TEE Core from an earlier call to
 * thread_enter_user_mode().
 */
uint32_t scall_sys_return_helper(uint32_t ret, bool panic, uint32_t panic_code,
				 struct thread_scall_regs *regs);

/* Saves TA panic stack, arch-specific implementation */
void scall_save_panic_stack(struct thread_scall_regs *regs);

#endif /*__KERNEL_SCALL_H*/
