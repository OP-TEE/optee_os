// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * PIL anti-rollback fuse policy. The fuse layout is the platform's, behind
 * the accessors in <platform>/qfprom_pil_arb.c.
 */

#include <inttypes.h>
#include <trace.h>

#include "qfprom_priv.h"

TEE_Result qcom_secboot_get_pil_rollback_version(uint32_t *version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool enabled = false;

	if (!version)
		return TEE_ERROR_BAD_PARAMETERS;

	*version = 0;

	res = qfprom_target_pil_arb_enabled(&enabled);
	if (res)
		return res;
	if (!enabled)
		return TEE_SUCCESS;

	return qfprom_target_get_pil_arb(version);
}

TEE_Result qcom_secboot_blow_pil_rollback_version(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Result cleanup_res = TEE_SUCCESS;
	bool enabled = false;

	res = qfprom_target_pil_arb_enabled(&enabled);
	if (res)
		return res;
	if (!enabled)
		return TEE_SUCCESS;

	res = qfprom_hw_init();
	if (res)
		return res;

	res = qfprom_target_blow_pil_arb(version);

	cleanup_res = qfprom_hw_deinit();
	if (cleanup_res)
		EMSG("PAS ARB: programming cleanup failed: %#"PRIx32,
		     cleanup_res);
	if (!res)
		res = cleanup_res;
	if (res) {
		EMSG("PAS ARB: programming failed: %#"PRIx32, res);
		EMSG("PAS ARB: fuses may be partially programmed");
		return res;
	}

	DMSG("PAS ARB: fuse update completed");

	return TEE_SUCCESS;
}
