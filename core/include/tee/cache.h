/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef __TEE_CACHE_H
#define __TEE_CACHE_H

#include <utee_types.h>

TEE_Result cache_operation(enum utee_cache_operation op, void *va, size_t len);

#endif /* __TEE_CACHE_H */
