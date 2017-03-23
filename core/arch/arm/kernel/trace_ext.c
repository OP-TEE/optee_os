/*
 * Copyright (c) 2014, Linaro Limited
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
#include <stdbool.h>
#include <trace.h>
#include <console.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>

const char trace_ext_prefix[] = "TEE-CORE";
int trace_level = TRACE_LEVEL;
static unsigned int puts_lock = SPINLOCK_UNLOCK;

void trace_ext_puts(const char *str)
{
	uint32_t itr_status = thread_mask_exceptions(THREAD_EXCP_ALL);
	bool mmu_enabled = cpu_mmu_enabled();
	bool was_contended = false;
	const char *p;

	if (mmu_enabled && !cpu_spin_trylock(&puts_lock)) {
		was_contended = true;
		cpu_spin_lock(&puts_lock);
	}

	console_flush();

	if (was_contended)
		console_putc('*');

	for (p = str; *p; p++)
		console_putc(*p);

	console_flush();

	if (mmu_enabled)
		cpu_spin_unlock(&puts_lock);

	thread_unmask_exceptions(itr_status);
}

int trace_ext_get_thread_id(void)
{
	return thread_get_id_may_fail();
}
