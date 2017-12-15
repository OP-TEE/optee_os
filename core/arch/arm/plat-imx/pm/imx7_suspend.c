// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
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
#include <arm.h>
#include <arm32.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx.h>
#include <imx_pm.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <sm/sm.h>
#include <sm/pm.h>
#include <sm/psci.h>
#include <stdint.h>

static int suspended_init;

int imx7_cpu_suspend(uint32_t power_state __unused, uintptr_t entry,
		     uint32_t context_id __unused, struct sm_nsec_ctx *nsec)
{
	uint32_t suspend_ocram_base = core_mmu_get_va(TRUSTZONE_OCRAM_START +
						      SUSPEND_OCRAM_OFFSET,
						      MEM_AREA_TEE_COHERENT);
	struct imx7_pm_info *p = (struct imx7_pm_info *)suspend_ocram_base;
	int ret;

	if (!suspended_init) {
		imx7_suspend_init();
		suspended_init = 1;
	}

	/* Store non-sec ctx regs */
	sm_save_modes_regs(&nsec->mode_regs);

	ret = sm_pm_cpu_suspend((uint32_t)p, (int (*)(uint32_t))
				(suspend_ocram_base + sizeof(*p)));
	/*
	 * Sometimes sm_pm_cpu_suspend may not really suspended,
	 * we need to check it's return value to restore reg or not
	 */
	if (ret < 0) {
		DMSG("=== Not suspended, GPC IRQ Pending ===\n");
		return 0;
	}

	plat_cpu_reset_late();

	/* Restore register of different mode in secure world */
	sm_restore_modes_regs(&nsec->mode_regs);

	/* Set entry for back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

	DMSG("=== Back from Suspended ===\n");

	return 0;
}
