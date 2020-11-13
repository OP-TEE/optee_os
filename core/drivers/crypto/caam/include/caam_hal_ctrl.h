/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
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

/*
 * Returns the number of Public Key module supported
 *
 * @baseaddr  Controller base address
 */
uint8_t caam_hal_ctrl_pknum(vaddr_t baseaddr);

/*
 * Returns if the HW support the split key operation.
 *
 * @baseaddr  Controller base address
 */
bool caam_hal_ctrl_splitkey_support(vaddr_t baseaddr);

/*
 * Returns the CAAM Era
 *
 * @baseaddr  Controller base address
 */
uint8_t caam_hal_ctrl_era(vaddr_t baseaddr);

/*
 * Increment the CAAM PRIBLOB field
 *
 * @baseaddr  Controller base address
 */
void caam_hal_ctrl_inc_priblob(vaddr_t baseaddr);
#endif /* __CAAM_HAL_CTRL_H__ */
