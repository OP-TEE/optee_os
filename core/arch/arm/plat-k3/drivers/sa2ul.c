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

#include "sa2ul.h"

#define	SA2UL_ES                0x0008
#define SA2UL_ES_TRNG           BIT(3)
#define	SA2UL_EEC               0x1000
#define SA2UL_EEC_TRNG          BIT(3)

#define FW_ENABLE_REGION        0x0a
#define FW_BACKGROUND_REGION    BIT(8)
#define FW_BIG_ARM_PRIVID       0x01
#define FW_TIFS_PRIVID          0xca
#define FW_WILDCARD_PRIVID      0xc3
#define FW_SECURE_ONLY          GENMASK_32(7, 0)
#define FW_NON_SECURE           GENMASK_32(15, 0)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SA2UL_BASE, SA2UL_REG_SIZE);

static TEE_Result sa2ul_init(void)
{
	vaddr_t sa2ul = (vaddr_t)phys_to_virt(SA2UL_BASE, MEM_AREA_IO_SEC,
					      RNG_REG_SIZE);
	uint16_t fwl_id = SA2UL_TI_SCI_FW_ID;
	uint16_t sa2ul_region = SA2UL_TI_SCI_FW_RGN_ID;
	uint16_t rng_region = RNG_TI_SCI_FW_RGN_ID;
	uint8_t owner_index = OPTEE_HOST_ID;
	uint8_t owner_privid = 0;
	uint16_t owner_permission_bits = 0;
	uint32_t control = 0;
	uint32_t permissions[FWL_MAX_PRIVID_SLOTS] = { };
	uint32_t num_perm = 0;
	uint64_t start_address = 0;
	uint64_t end_address = 0;
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

	/* Try to claim the SA2UL firewall for ourselves */
	ret = ti_sci_change_fwl_owner(fwl_id, sa2ul_region, owner_index,
				      &owner_privid, &owner_permission_bits);
	if (ret) {
		/*
		 * This is not fatal, it just means we are on an HS device
		 * where the DMSC already owns the SA2UL. On GP we need
		 * to do additional setup for access permissions below.
		 */
		DMSG("Could not change SA2UL firewall owner");
	} else {
		IMSG("Fixing SA2UL firewall owner for GP device");

		/* Get current SA2UL firewall configuration */
		ret = ti_sci_get_fwl_region(fwl_id, sa2ul_region, 1,
					    &control, permissions,
					    &start_address, &end_address);
		if (ret) {
			EMSG("Could not get firewall region information");
			return TEE_ERROR_GENERIC;
		}

		/* Modify SA2UL firewall to allow all others access*/
		control = FW_BACKGROUND_REGION | FW_ENABLE_REGION;
		permissions[0] = (FW_WILDCARD_PRIVID << 16) | FW_NON_SECURE;
		ret = ti_sci_set_fwl_region(fwl_id, sa2ul_region, 1,
					    control, permissions,
					    0x0, UINT32_MAX);
		if (ret) {
			EMSG("Could not set firewall region information");
			return TEE_ERROR_GENERIC;
		}
	}

	/* Claim the TRNG firewall for ourselves */
	ret = ti_sci_change_fwl_owner(fwl_id, rng_region, owner_index,
				      &owner_privid, &owner_permission_bits);
	if (ret) {
		EMSG("Could not change TRNG firewall owner");
		return TEE_ERROR_GENERIC;
	}

	/* Get current TRNG firewall configuration */
	ret = ti_sci_get_fwl_region(fwl_id, rng_region, 1,
				    &control, permissions,
				    &start_address, &end_address);
	if (ret) {
		EMSG("Could not get firewall region information");
		return TEE_ERROR_GENERIC;
	}

	/* Modify TRNG firewall to block all others access */
	control = FW_ENABLE_REGION;
	start_address = RNG_BASE;
	end_address = RNG_BASE + RNG_REG_SIZE - 1;
	permissions[num_perm++] = (FW_BIG_ARM_PRIVID << 16) | FW_SECURE_ONLY;
#if defined(PLATFORM_FLAVOR_am62x)
	permissions[num_perm++] = (FW_TIFS_PRIVID << 16) | FW_NON_SECURE;
#endif
	ret = ti_sci_set_fwl_region(fwl_id, rng_region, num_perm,
				    control, permissions,
				    start_address, end_address);
	if (ret) {
		EMSG("Could not set firewall region information");
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
	result = sa2ul_rng_init();
	if (result != TEE_SUCCESS)
		return result;

	IMSG("SA2UL Drivers initialized");

	return TEE_SUCCESS;
}
driver_init(sa2ul_init);
