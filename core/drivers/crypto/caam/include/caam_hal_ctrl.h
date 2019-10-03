/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Controller Hardware Abstration Layer header.
 */
#ifndef __CAAM_HAL_CTRL_H__
#define __CAAM_HAL_CTRL_H__

#include <types_ext.h>

/*
 * Initializes the CAAM HW Controller
 *
 * @baseaddr  Controller base address
 */
void caam_hal_ctrl_init(vaddr_t baseaddr);

/*
 * Returns the number of Job Ring supported
 *
 * @baseaddr  Controller base address
 */
uint8_t caam_hal_ctrl_jrnum(vaddr_t baseaddr);

/*
 * If Hash operation is supported, returns the Maximum Hash Algorithm
 * supported by the HW else UINT8_MAX
 *
 * @baseaddr  Controller base address
 */
uint8_t caam_hal_ctrl_hash_limit(vaddr_t baseaddr);

#endif /* __CAAM_HAL_CTRL_H__ */
