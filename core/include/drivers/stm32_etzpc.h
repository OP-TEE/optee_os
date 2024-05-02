/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2014, ARM Limited and Contributors. All rights reserved.
 * Copyright (c) 2018-2019, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_ETZPC_H
#define __DRIVERS_STM32_ETZPC_H

#include <util.h>
#include <types_ext.h>

enum etzpc_decprot_attributes {
	ETZPC_DECPROT_S_RW = 0,
	ETZPC_DECPROT_NS_R_S_W = 1,
	ETZPC_DECPROT_MCU_ISOLATION = 2,
	ETZPC_DECPROT_NS_RW = 3,
	ETZPC_DECPROT_MAX = 4,
};

/*
 * Get the DECPROT attribute
 * @decprot_id: ID that is the index of the DECPROT in the ETZPC interface
 * Return attribute of this DECPROT
 */
enum etzpc_decprot_attributes etzpc_get_decprot(uint32_t decprot_id);

/*
 * Configure the target TZMA secure memory range
 * @tzma_id: ID that is the index of the TZMA in the ETZPC interface
 * @tzma_value: Secure memory secure size in 4kByte page size. Note that this
 * is an offset from the memory base address
 */
void etzpc_configure_tzma(uint32_t tzma_id, uint16_t tzma_value);

#endif /*__DRIVERS_STM32_ETZPC_H*/
