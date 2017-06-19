/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <compiler.h>
#include <kernel/thread.h>
#include <kernel/wait_queue.h>
#include <sm/tee_mon.h>
#include <tee_api_types.h>
#include <tee/arch_svc.h>
#include <tee/entry_std.h>

#include "thread_private.h"

void __section(".text.dummy.tee_svc_handler")
tee_svc_handler(struct thread_svc_regs *regs __unused)
{
}

void __section(".text.dummy.tee_entry_std")
tee_entry_std(struct thread_smc_args *smc_args __unused)
{
}

TEE_Result __section(".text.dummy.init_teecore") init_teecore(void)
{
	return TEE_SUCCESS;
}

void __section(".text.dummy.__thread_std_smc_entry")
__thread_std_smc_entry(struct thread_smc_args *args __unused)
{
}
void __section(".text.dummy.__wq_rpc")
__wq_rpc(uint32_t func __unused, int id __unused,
	 const void *sync_obj __unused, int owner __unused,
	 const char *fname __unused, int lineno  __unused)
{
}
