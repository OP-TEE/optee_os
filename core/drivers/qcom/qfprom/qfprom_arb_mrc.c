// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

/*
 * PIL anti-rollback and multi-root certificate (MRC) fuse policy. The fuse
 * layout is the platform's: the anti-rollback accessors in
 * <platform>/qfprom_pil_arb.c and the MRC rows in qfprom_target.h.
 */

#include <inttypes.h>
#include <trace.h>

#include "qfprom_priv.h"

/* Is secure boot on and PIL anti-rollback enabled for this device? */
static TEE_Result pil_arb_is_active(bool *active)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool secboot = false;

	*active = false;

	res = qcom_secboot_is_enabled(&secboot);
	if (res)
		return res;
	if (!secboot)
		return TEE_SUCCESS;

	return qfprom_target_pil_arb_enabled(active);
}

TEE_Result qcom_secboot_get_pil_rollback_version(uint32_t *version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool active = false;

	if (!version)
		return TEE_ERROR_BAD_PARAMETERS;

	*version = 0;

	res = pil_arb_is_active(&active);
	if (res)
		return res;
	if (!active)
		return TEE_SUCCESS;

	return qfprom_target_get_pil_arb(version);
}

TEE_Result qcom_secboot_blow_pil_rollback_version(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Result cleanup_res = TEE_SUCCESS;
	bool active = false;

	res = pil_arb_is_active(&active);
	if (res)
		return res;
	if (!active)
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

TEE_Result qcom_secboot_get_mrc_info(struct qcom_secboot_mrc_info *info)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t total = 1;
	uint32_t val = 0;

	if (!info)
		return TEE_ERROR_BAD_PARAMETERS;

	/* MRC is off unless the fuses say otherwise: one root, no lists */
	info->num_roots = 1;
	info->activation_list = 0;
	info->revocation_list = 0;

	res = read_sense_reg(SECURE_BOOT_APPS_OFFSET, &val);
	if (res)
		return res;
	if (!(val & SECURE_BOOT_PK_HASH_IN_FUSE_BMSK))
		return TEE_SUCCESS;

	res = read_sense_reg(OEM_CONFIG0_OFFSET, &val);
	if (res)
		return res;

	/* The first root is implicit, the field counts the others */
	total += (val & ROOT_CERT_TOTAL_NUM_BMSK) >> ROOT_CERT_TOTAL_NUM_SHFT;
	if (total <= 1)
		return TEE_SUCCESS;

	res = read_sense_reg(MRC_ACTIVATION_LIST_OFFSET, &val);
	if (res)
		return res;
	info->activation_list = val & MRC_ROOT_CERT_LIST_BMSK;

	res = read_sense_reg(MRC_REVOCATION_LIST_OFFSET, &val);
	if (res)
		return res;
	info->revocation_list = val & MRC_ROOT_CERT_LIST_BMSK;

	info->num_roots = total;

	return TEE_SUCCESS;
}
