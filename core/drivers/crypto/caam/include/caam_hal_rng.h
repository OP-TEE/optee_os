/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019-2021 NXP
 *
 * Brief   CAAM Random Number Generator Hardware Abstration Layer.
 *         Implementation of primitives to access HW
 */
#ifndef __CAAM_HAL_RNG_H__
#define __CAAM_HAL_RNG_H__

#include <caam_status.h>
#include <types_ext.h>

/*
 * Returns if all RNG State Handler already instantiated or not
 *
 * @baseaddr  RNG Base Address
 */
enum caam_status caam_hal_rng_instantiated(vaddr_t baseaddr);

/*
 * Returns the number of RNG State Handle
 *
 * @baseaddr  RNG Base Address
 */
uint32_t caam_hal_rng_get_nb_sh(vaddr_t baseaddr);

/*
 * Returns the RNG Status State Handle
 *
 * @baseaddr  RNG Base Address
 */
uint32_t caam_hal_rng_get_sh_status(vaddr_t baseaddr);

/*
 * Returns true if the RNG Key is loaded, false otherwise
 *
 * @baseaddr  RNG Base Address
 */
bool caam_hal_rng_key_loaded(vaddr_t baseaddr);

/*
 * Configures the RNG entropy delay
 *
 * @baseaddr   RNG Base Address
 * @inc_delay  Entropy Delay incrementation
 */
enum caam_status caam_hal_rng_kick(vaddr_t baseaddr, uint32_t inc_delay);

#endif /* __CAAM_HAL_RNG_H__ */
