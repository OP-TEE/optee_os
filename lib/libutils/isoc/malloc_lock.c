/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <malloc.h>

#ifdef __KERNEL__
/* Compiling for TEE Core */
#include <kernel/spinlock.h>

unsigned int __malloc_spinlock = SPINLOCK_UNLOCK;

#endif /*__KERNEL__*/
