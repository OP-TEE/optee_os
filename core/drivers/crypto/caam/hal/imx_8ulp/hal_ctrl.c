// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 *
 * Brief   CAAM Controller Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <imx.h>
#include <io.h>
#include <caam_hal_ctrl.h>
#include <registers/ctrl_regs.h>

void caam_hal_ctrl_init(vaddr_t baseaddr)
{
	/* Enable DECO watchdogs */
	io_setbits32(baseaddr + MCFGR, MCFGR_WDE);
}
