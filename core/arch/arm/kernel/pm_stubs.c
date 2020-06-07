// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2020, Linaro Limited
 */

#include <compiler.h>
#include <keep.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>

unsigned long __noreturn pm_panic(unsigned long a0 __unused,
				  unsigned long a1 __unused)
{
	panic();
}
DECLARE_KEEP_PAGER(pm_panic);

unsigned long pm_do_nothing(unsigned long a0 __unused,
			    unsigned long a1 __unused)
{
	return 0;
}
DECLARE_KEEP_PAGER(pm_do_nothing);
