// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <arm32.h>
#include <io.h>
#include <imx_caam.h>
#include <kernel/generic_boot.h>
#include <platform_config.h>
#include <stdint.h>

static void init_csu(void)
{
	uintptr_t addr;

	/* first grant all peripherals */
	for (addr = CSU_BASE + CSU_CSL_START;
	     addr != CSU_BASE + CSU_CSL_END;
	     addr += 4)
		io_write32(addr, CSU_ACCESS_ALL);

	/* lock the settings */
	for (addr = CSU_BASE + CSU_CSL_START;
	     addr != CSU_BASE + CSU_CSL_END;
	     addr += 4)
		io_setbits32(addr, CSU_SETTING_LOCK);
}

/* MMU not enabled now */
void plat_cpu_reset_late(void)
{
	init_csu();
	init_caam();
}
