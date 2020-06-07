// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 */
#include <compiler.h>
#include <kernel/boot.h>
#include <kernel/thread.h>
#include <kernel/wait_queue.h>
#include <sm/tee_mon.h>
#include <tee_api_types.h>
#include <tee/arch_svc.h>
#include <tee/entry_std.h>

#include "thread_private.h"

void __section(".text.dummy.tee_svc_handler")
thread_svc_handler(struct thread_svc_regs *regs __unused)
{
}

TEE_Result __section(".text.dummy.init_teecore") init_teecore(void)
{
	return TEE_SUCCESS;
}

void __section(".text.dummy.paged_init_primary")
paged_init_primary(unsigned long fdt __unused)
{
}

uint32_t __section(".text.dummy.__thread_std_smc_entry")
__thread_std_smc_entry(uint32_t a0 __unused, uint32_t a1 __unused,
		       uint32_t a2 __unused, uint32_t a3 __unused)
{
	return 0;
}
void __section(".text.dummy.__wq_rpc")
__wq_rpc(uint32_t func __unused, int id __unused,
	 const void *sync_obj __unused, const char *fname __unused,
	 int lineno  __unused)
{
}
