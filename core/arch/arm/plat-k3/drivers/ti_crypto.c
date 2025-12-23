// SPDX-License-Identifier: BSD-2-Clause
/*
 * Texas Instruments Crypto Operations
 *
 * Copyright (C) 2025 Texas Instruments Incorporated - https://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#include <drivers/ti_sci.h>
#include <platform_config.h>
#include <trace.h>
#include "ti_crypto.h"

TEE_Result ti_crypto_init_rng_fwl(uint16_t fwl_id, uint16_t fwl_region)
{
	uint16_t rng_region = RNG_TI_SCI_FW_RGN_ID;
	uint8_t owner_index = OPTEE_HOST_ID;
	uint8_t owner_privid = 0;
	uint16_t owner_permission_bits = 0;
	uint32_t control = 0;
	uint32_t permissions[FWL_MAX_PRIVID_SLOTS] = { };
	uint32_t num_perm = 0;
	uint64_t start_address = 0;
	uint64_t end_address = 0;
	int ret = 0;

	/* Try to claim background firewall region for ourselves */
	ret = ti_sci_change_fwl_owner(fwl_id, fwl_region, owner_index,
				      &owner_privid, &owner_permission_bits);
	if (ret) {
		/*
		 * This is not fatal, it just means we are on an HS device
		 * where the DMSC already owns the accelerator. On GP we need
		 * to do additional setup for access permissions below.
		 */
		DMSG("Could not change Security Accelerator firewall owner");
	} else {
		IMSG("Fixing background firewall owner");

		/* Modify current firewall configuration */
		control = FW_BACKGROUND_REGION | FW_ENABLE_REGION;
		permissions[0] = (FW_WILDCARD_PRIVID << 16) | FW_NON_SECURE;
		ret = ti_sci_set_fwl_region(fwl_id, fwl_region, 1,
					    control, permissions,
					    0x0, UINT32_MAX);

		if (ret) {
			EMSG("Could not set firewall region information");
			return TEE_ERROR_GENERIC;
		}
	}

	/* Claim the TRNG firewall configurations */
	ret = ti_sci_change_fwl_owner(fwl_id, rng_region, owner_index,
				      &owner_privid, &owner_permission_bits);
	if (ret) {
		EMSG("Could not change TRNG firewall owner");
		return TEE_ERROR_GENERIC;
	}

	/* Modify TRNG firewall to block all others access */
	control = FW_ENABLE_REGION;
	start_address = RNG_BASE;
	end_address = RNG_BASE + RNG_REG_SIZE - 1;
	permissions[num_perm++] = (FW_BIG_ARM_PRIVID << 16) | FW_SECURE_ONLY;
	permissions[num_perm++] = (FW_TIFS_PRIVID << 16) | FW_NON_SECURE;
	ret = ti_sci_set_fwl_region(fwl_id, rng_region, num_perm, control,
				    permissions, start_address, end_address);
	if (ret) {
		EMSG("Could not set firewall region information");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
