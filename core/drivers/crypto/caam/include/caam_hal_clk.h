/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Clock functions header.
 */
#ifndef __CAAM_HAL_CLK_H__
#define __CAAM_HAL_CLK_H__

#include <types_ext.h>

/*
 * Enable/disable the CAAM clocks
 *
 * @enable  Enable the clock if true
 */
void caam_hal_clk_enable(bool enable);

#endif /* __CAAM_HAL_CLK_H__ */
