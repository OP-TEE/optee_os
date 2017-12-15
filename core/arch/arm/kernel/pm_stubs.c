// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <compiler.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>

unsigned long pm_panic(unsigned long a0 __unused, unsigned long a1 __unused)
{
	panic();
}

unsigned long pm_do_nothing(unsigned long a0 __unused,
			    unsigned long a1 __unused)
{
	return 0;
}
