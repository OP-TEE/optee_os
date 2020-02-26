// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */
#include <compiler.h>
#include <kernel/generic_boot.h>

unsigned long __section(".text.dummy.get_aslr_seed")
get_aslr_seed(void *fdt __unused)
{
	return 0;
}
