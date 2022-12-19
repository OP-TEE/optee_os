/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef ARCH_SVC_PRIVATE_H
#define ARCH_SVC_PRIVATE_H

#include <tee_api_types.h>

/*
 * Generic "pointer to function" type. Actual syscalls take zero or more
 * arguments and return TEE_Result.
 */
typedef void (*syscall_t)(void);

/* Helper function for scall_handle_user_ta() and scall_handle_ldelf() */
uint32_t scall_do_call(struct thread_scall_regs *regs, syscall_t func);

#endif /*ARCH_SVC_PRIVATE_H*/
