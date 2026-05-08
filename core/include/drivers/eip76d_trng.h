/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Texas Instruments K3 EIP76D TRNG Driver
 *
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#ifndef __DRIVERS_EIP76D_TRNG_H
#define __DRIVERS_EIP76D_TRNG_H

#include <tee_api_types.h>

TEE_Result eip76d_rng_init(void);

#endif /* __DRIVERS_EIP76D_TRNG_H */
