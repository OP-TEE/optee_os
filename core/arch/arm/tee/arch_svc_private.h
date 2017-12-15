/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef ARCH_SVC_PRIVATE_H
#define ARCH_SVC_PRIVATE_H

#include <tee_api_types.h>

/* void argument but in reality it can be any number of arguments */
typedef TEE_Result (*syscall_t)(void);

/* Helper function for tee_svc_handler() */
uint32_t tee_svc_do_call(struct thread_svc_regs *regs, syscall_t func);

#endif /*ARCH_SVC_PRIVATE_H*/
