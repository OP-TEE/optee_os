/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef TEE_ARCH_SVC_H
#define TEE_ARCH_SVC_H

struct thread_svc_regs;

void tee_svc_handler(struct thread_svc_regs *regs);

/*
 * Called from the assembly functions syscall_sys_return() and
 * syscall_panic() to update the register values in the struct
 * thread_svc_regs to return back to TEE Core from an erlier call to
 * thread_enter_user_mode().
 */
uint32_t tee_svc_sys_return_helper(uint32_t ret, bool panic,
			uint32_t panic_code, struct thread_svc_regs *regs);

#endif /*TEE_ARCH_SVC_H*/
