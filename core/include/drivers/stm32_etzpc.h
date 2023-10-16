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

#define ETZPC_TZMA_ALL_SECURE		GENMASK_32(9, 0)
#define ETZPC_TZMA_ALL_NO_SECURE	0x0

/*
 * Load a DECPROT configuration
 * @decprot_id: ID that is the index of the DECPROT in the ETZPC interface
 * @decprot_attr: Restriction access attributes
 */
void etzpc_configure_decprot(uint32_t decprot_id,
			     enum etzpc_decprot_attributes decprot_attr);

/*
 * Get the DECPROT attribute
 * @decprot_id: ID that is the index of the DECPROT in the ETZPC interface
 * Return attribute of this DECPROT
 */
enum etzpc_decprot_attributes etzpc_get_decprot(uint32_t decprot_id);

/*
 * Lock access to the DECPROT attributes
 * @decprot_id: ID that is the index of the DECPROT in the ETZPC interface
 */
void etzpc_lock_decprot(uint32_t decprot_id);

/*
 * Return the lock status of the target DECPROT
 * @decprot_id: ID that is the index of the DECPROT in the ETZPC interface
 */
bool etzpc_get_lock_decprot(uint32_t decprot_id);

/*
 * Configure the target TZMA read only size
 * @tzma_id: ID that is the index of the TZMA in the ETZPC interface
 * @tzma_value: Read-only size
 */
void etzpc_configure_tzma(uint32_t tzma_id, uint16_t tzma_value);

/*
 * Get the target TZMA read only size
 * @tzma_id: ID that is the index of the TZMA in the ETZPC interface
 * Return the size of read-only area
 */
uint16_t etzpc_get_tzma(uint32_t tzma_id);

/*
 * Lock the target TZMA
 * @tzma_id: ID that is the index of the TZMA in the ETZPC interface
 */
void etzpc_lock_tzma(uint32_t tzma_id);

/*
 * Return the lock status of the target TZMA
 * @tzma_id: ID that is the index of the TZMA in the ETZPC interface
 * Return true if TZMA is locked, false otherwise
 */
bool etzpc_get_lock_tzma(uint32_t tzma_id);
#endif /*__DRIVERS_STM32_ETZPC_H*/
