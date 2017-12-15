/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef PM_STUBS_H
#define PM_STUBS_H

#include <stdint.h>
#include <compiler.h>

unsigned long pm_panic(unsigned long a0, unsigned long a1);
unsigned long pm_do_nothing(unsigned long a0, unsigned long a1);

#endif /* PM_STUBS_H */
