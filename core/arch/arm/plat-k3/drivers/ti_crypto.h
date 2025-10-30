/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Texas Instruments Incorporated - https://www.ti.com/
 *	Suhaas Joshi <s-joshi@ti.com>
 */

#ifndef DRIVERS_TI_CRYPTO_H
#define DRIVERS_TI_CRYPTO_H

#include <stdint.h>
#include <tee_api_types.h>

/**
 * ti_crypto_init_rng_fwl() - Initialize RNG firewall in SA2UL/DTHEv2
 *
 * Sets the firewall for the RNG region in SA2UL/DTHEv2 to allow access by only
 * the secure world.
 *
 * @fwl_id:		Firewall identifier
 * @sec_accel_region:	Firewall region index
 *
 * Return: TEE_SUCCESS if all goes well, else appropriate error message.
 */
TEE_Result ti_crypto_init_rng_fwl(uint16_t fwl_id, uint16_t sec_accel_region);

#endif
