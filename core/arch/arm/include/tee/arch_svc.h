/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */
#ifndef TEE_ARCH_SVC_H
#define TEE_ARCH_SVC_H

struct thread_scall_regs;

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

#endif /*TEE_ARCH_SVC_H*/
