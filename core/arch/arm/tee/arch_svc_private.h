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

/* Helper function for user_ta_handle_svc() */
uint32_t tee_svc_do_call(struct thread_svc_regs *regs, syscall_t func);

#endif /*ARCH_SVC_PRIVATE_H*/
