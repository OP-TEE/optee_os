// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2019 NXP
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

#include <imx.h>
#include <io.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <kernel/tz_ssvce_def.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SRC_BASE, CORE_MMU_PGDIR_SIZE);

void plat_cpu_reset_late(void)
{
	uint32_t pa __maybe_unused;

	if (!get_core_pos()) {
		/* primary core */
#if defined(CFG_BOOT_SYNC_CPU)
		pa = virt_to_phys((void *)TEE_TEXT_VA_START);
		/* set secondary entry address and release core */
		io_write32(SRC_BASE + SRC_GPR1 + 8, pa);
		io_write32(SRC_BASE + SRC_GPR1 + 16, pa);
		io_write32(SRC_BASE + SRC_GPR1 + 24, pa);

		io_write32(SRC_BASE + SRC_SCR, SRC_SCR_CPU_ENABLE_ALL);
#endif
		imx_configure_tzasc();
	}
}
