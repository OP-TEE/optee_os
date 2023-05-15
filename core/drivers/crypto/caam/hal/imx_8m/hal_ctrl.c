// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Controller Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_ctrl.h>
#include <caam_io.h>
#include <registers/ctrl_regs.h>

void caam_hal_ctrl_init(vaddr_t baseaddr)
{
	/* Enable DECO watchdogs */
	io_setbits32(baseaddr + MCFGR, MCFGR_WDE);
}
