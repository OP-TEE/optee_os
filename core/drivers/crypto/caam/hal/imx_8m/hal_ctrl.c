// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018-2019 NXP
 *
 * @file    hal_ctrl.c
 *
 * @brief   CAAM Controller Hardware Abstration Layer.\n
 *          Implementation of primitives to access HW
 */
/* Local includes */
#include "caam_io.h"

/* Hal includes */
#include "hal_ctrl.h"

/* Register includes */
#include "ctrl_regs.h"

/**
 * @brief   Initializes the CAAM HW Controller
 *
 * @param[in] baseaddr  Controller base address
 */
void hal_ctrl_init(vaddr_t baseaddr)
{
	/*
	 * Enable DECO watchdogs
	 */
	io_mask32(baseaddr + MCFGR, MCFGR_WDE, MCFGR_WDE);
}

