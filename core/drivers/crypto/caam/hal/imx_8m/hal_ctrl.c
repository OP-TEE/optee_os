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

/*
 * Initializes the CAAM HW Controller
 *
 * @baseaddr  Controller base address
 */
void caam_hal_ctrl_init(vaddr_t baseaddr)
{
	/* Enable DECO watchdogs */
	io_mask32(baseaddr + MCFGR, MCFGR_WDE, MCFGR_WDE);
}
