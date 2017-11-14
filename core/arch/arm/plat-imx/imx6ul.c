// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2018 NXP
 * Peng Fan <peng.fan@nxp.com>
 */

#include <imx.h>
#include <kernel/generic_boot.h>
#include <platform_config.h>


/* MMU not enabled now */
void plat_cpu_reset_late(void)
{
#ifdef CFG_CSU
	csu_init();
#endif
}
