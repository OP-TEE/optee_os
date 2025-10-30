// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments K3 SA2UL Driver
 *
 * Copyright (C) 2022 Texas Instruments Incorporated - https://www.ti.com/
 *	Andrew Davis <afd@ti.com>
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
#include "ti_crypto.h"

#define	SA2UL_ES                0x0008
#define SA2UL_ES_TRNG           BIT(3)
#define	SA2UL_EEC               0x1000
#define SA2UL_EEC_TRNG          BIT(3)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SA2UL_BASE, SA2UL_REG_SIZE);

static TEE_Result sa2ul_init(void)
{
	vaddr_t sa2ul = (vaddr_t)phys_to_virt(SA2UL_BASE, MEM_AREA_IO_SEC,
					      RNG_REG_SIZE);
	uint32_t val = 0;
	TEE_Result result = TEE_SUCCESS;
	int ret = 0;

	if (SA2UL_TI_SCI_DEV_ID != -1) {
		/* Power on the SA2UL device */
		ret = ti_sci_device_get(SA2UL_TI_SCI_DEV_ID);
		if (ret) {
			EMSG("Failed to get SA2UL device");
			return TEE_ERROR_GENERIC;
		}
	}

	IMSG("Activated SA2UL device");

	result = ti_crypto_init_rng_fwl(SA2UL_TI_SCI_FW_ID,
					SA2UL_TI_SCI_FW_RGN_ID);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to enable firewalls for TRNG device");
		return TEE_ERROR_GENERIC;
	}

	IMSG("Enabled firewalls for SA2UL TRNG device");

	/* Enable RNG engine in SA2UL if not already enabled */
	val = io_read32(sa2ul + SA2UL_ES);
	if (!(val & SA2UL_ES_TRNG)) {
		IMSG("Enabling SA2UL TRNG engine");
		io_setbits32(sa2ul + SA2UL_EEC, SA2UL_EEC_TRNG);
	}

	/* Initialize the RNG Module */
	result = eip76d_rng_init();
	if (result != TEE_SUCCESS)
		return result;

	IMSG("SA2UL Drivers initialized");

	return TEE_SUCCESS;
}
service_init_crypto(sa2ul_init);
