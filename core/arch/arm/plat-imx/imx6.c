// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2018 NXP
 */
#include <imx.h>
#include <io.h>
#include <kernel/tz_ssvce_pl310.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>

register_phys_mem(MEM_AREA_IO_SEC, SRC_BASE, CORE_MMU_DEVICE_SIZE);

void plat_cpu_reset_late(void)
{
	uint32_t pa __maybe_unused;

	if (!get_core_pos()) {
		/* primary core */
#if defined(CFG_BOOT_SYNC_CPU)
		pa = virt_to_phys((void *)TEE_TEXT_VA_START);
		/* set secondary entry address and release core */
		write32(pa, SRC_BASE + SRC_GPR1 + 8);
		write32(pa, SRC_BASE + SRC_GPR1 + 16);
		write32(pa, SRC_BASE + SRC_GPR1 + 24);

		write32(BM_SRC_SCR_CPU_ENABLE_ALL, SRC_BASE + SRC_SCR);
#endif

		/* SCU config */
		write32(SCU_INV_CTRL_INIT, SCU_BASE + SCU_INV_SEC);
		write32(SCU_SAC_CTRL_INIT, SCU_BASE + SCU_SAC);
		write32(SCU_NSAC_CTRL_INIT, SCU_BASE + SCU_NSAC);

		/* SCU enable */
		write32(read32(SCU_BASE + SCU_CTRL) | 0x1,
			SCU_BASE + SCU_CTRL);

#ifdef CFG_CSU
		/* configure imx6 CSU */
		csu_init();
#endif
	}
}
