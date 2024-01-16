// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */
#include <compiler.h>
#include <kernel/boot.h>
#include <mm/core_mmu.h>

void __section(".text.dummy.boot_save_boot_info")
boot_save_args(unsigned long a0 __unused, unsigned long a1 __unused,
	       unsigned long a2 __unused, unsigned long a3 __unused,
	       unsigned long a4 __unused)
{
}

unsigned long __section(".text.dummy.get_aslr_seed")
get_aslr_seed(void)
{
	return 0;
}

void __section(".text.dummy.core_init_mmu_map")
core_init_mmu_map(unsigned long seed __unused,
		  struct core_mmu_config *cfg __unused)
{
}

void __section(".text.dummy.boot_init_primary_early")
boot_init_primary_early(void)
{
}
