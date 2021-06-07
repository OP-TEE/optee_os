/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Bootlin
 */

#ifndef SAM_SFR_H
#define SAM_SFR_H

#include <util.h>

/* L2 cache RAM used as an internal SRAM */
#define AT91_SFR_L2CC_HRAMC		0x58

vaddr_t sam_sfr_base(void);

#endif
