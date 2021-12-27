// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <compiler.h>
#include <initcall.h>
#include <kernel/thread.h>
#include <mm/mobj.h>

/* satisfy notif_(rpc,wait,send_sync) */
uint32_t thread_rpc_cmd(uint32_t cmd __unused, size_t num_params __unused,
			struct thread_param *params __unused)
{
	return 0;
}

void pgt_init(void)
{
}

bool arch_va2pa_helper(void *va __unused, paddr_t *pa __unused)
{
	return false;
}

bool core_mmu_user_mapping_is_active(void)
{
	return false;
}
