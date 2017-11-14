// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */
#include <imx.h>
#include <kernel/generic_boot.h>
#include <kernel/misc.h>
#include <platform_config.h>

void plat_cpu_reset_late(void)
{
	if (get_core_pos() != 0)
		return;

#ifdef CFG_CSU
	csu_init();
#endif
}
