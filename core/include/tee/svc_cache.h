/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef __TEE_SVC_CACHE_H
#define __TEE_SVC_CACHE_H

#include <types_ext.h>
#include <tee_api_types.h>

#ifdef CFG_CACHE_API
TEE_Result syscall_cache_operation(void *va, size_t len, unsigned long op);
#else
#define  syscall_cache_operation syscall_not_supported
#endif

#endif /*__TEE_SVC_CACHE_H*/
