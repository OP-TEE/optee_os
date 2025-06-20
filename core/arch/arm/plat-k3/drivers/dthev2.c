// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments K3 DTHEV2 Driver
 *
 * Copyright (C) 2025 Texas Instruments Incorporated - https://www.ti.com/
 *	T Pratham <t-pratham@ti.com>
 */

#include <drivers/ti_sci.h>
#include <initcall.h>
#include <io.h>
#include <keep.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <rng_support.h>

#include "eip76d_trng.h"

static TEE_Result dthev2_init(void)
{
	TEE_Result result = TEE_SUCCESS;

	/* Initialize the RNG Module */
	result = eip76d_rng_init();
	if (result != TEE_SUCCESS)
		return result;

	IMSG("DTHEv2 Drivers initialized");

	return TEE_SUCCESS;
}
service_init_crypto(dthev2_init);
