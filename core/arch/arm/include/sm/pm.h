/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017 NXP
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

#ifndef __SM_PM_H
#define __SM_PM_H
#include <stdint.h>
#include <types_ext.h>

struct sm_pm_ctx {
	uint32_t sp;
	paddr_t cpu_resume_addr;
	uint32_t suspend_regs[16];
};

/* suspend/resume core functions */
void sm_pm_cpu_suspend_save(struct sm_pm_ctx *ptr, uint32_t sp);
void sm_pm_cpu_do_suspend(uint32_t *ptr);
void sm_pm_cpu_do_resume(void);

/*
 * Exported to platform suspend, arg will be passed to fn as r0
 * Return value: 0  - cpu resumed from suspended state.
 *               -1 - cpu not suspended.
 */
int sm_pm_cpu_suspend(uint32_t arg, int (*fn)(uint32_t));
#endif
