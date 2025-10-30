/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Texas Instruments Incorporated - https://www.ti.com/
 *	Suhaas Joshi <s-joshi@ti.com>
 */

#ifndef TI_CRYPTO_H
#define TI_CRYPTO_H

#include <compiler.h>
#include <stdint.h>
#include <util.h>
#include <io.h>
#include <initcall.h>
/**
 * ti_crypto_init_rng_fwl() - Initialize RNG firewall in SA2UL/DTHEv2
 *
 * Sets the firewall for the RNG region in SA2UL/DTHEv2 to allow access by only
 * the secure world.
 *
 * Return: TEE_SUCCESS if all goes well, else appropriate error message.
 */
TEE_Result ti_crypto_init_rng_fwl(uint16_t fwl_id, uint16_t sec_accel_region);

#endif
