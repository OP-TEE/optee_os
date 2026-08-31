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
#include <io.h>
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

/*
 * Set the MRC region's bit in QFPROM_WRITE_DISABLE_STICKY_BIT0. It is a
 * control bit, not a fuse sense register: once set it blocks further writes
 * to the region until the next reset.
 */
static TEE_Result lock_mrc_region(void)
{
	struct qfprom_context *drv = qfprom_get_context();

	if (!drv->raw_base)
		return TEE_ERROR_BAD_STATE;

	io_write32(drv->raw_base + MRC_STICKY_BIT_OFFSET, MRC_STICKY_BIT_BMSK);

	return TEE_SUCCESS;
}

static TEE_Result qcom_secboot_blow_mrc_fuses(uint32_t activation_list,
					      uint32_t revocation_list)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Result cleanup_res = TEE_SUCCESS;
	uint32_t row[2] = { };

	res = qfprom_read_row_locked(MRC_ACTIVATION_LIST_RAW_ADDR,
				     QFPROM_ADDR_SPACE_RAW, row);
	if (res) {
		EMSG("MRC: activation list read failed: %#"PRIx32, res);
		return res;
	}

	/* Existing activation must be locked even without new requests. */
	if (!activation_list && !revocation_list && !row[0])
		return TEE_SUCCESS;

	if (activation_list & ~MRC_ROOT_CERT_LIST_BMSK ||
	    revocation_list & ~MRC_ROOT_CERT_LIST_BMSK) {
		EMSG("MRC: activation/revocation list out of range: %#"PRIx32
		     "/%#"PRIx32, activation_list, revocation_list);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = qfprom_hw_init();
	if (res)
		return res;

	/* Antifuse writes only set bits; safe to write the bitmap directly. */
	row[0] = activation_list;
	row[1] = 0;
	res = qfprom_write_row(MRC_ACTIVATION_LIST_RAW_ADDR, row);
	if (res) {
		EMSG("MRC: activation list fuse write failed: %#"PRIx32, res);
		goto out;
	}

	row[0] = revocation_list;
	res = qfprom_write_row(MRC_REVOCATION_LIST_RAW_ADDR, row);
	if (res) {
		EMSG("MRC: revocation list fuse write failed: %#"PRIx32, res);
		goto out;
	}

	res = lock_mrc_region();
	if (res)
		EMSG("MRC: failed to set sticky bit: %#"PRIx32, res);

out:
	cleanup_res = qfprom_hw_deinit();
	if (cleanup_res)
		EMSG("MRC: programming cleanup failed: %#"PRIx32, cleanup_res);
	if (res || cleanup_res)
		EMSG("MRC: fuses may be partially programmed");
	return res ? res : cleanup_res;
}

TEE_Result qcom_secboot_provision_mrc_fuses(void)
{
	return qcom_secboot_blow_mrc_fuses(CFG_QCOM_MRC_ACTIVATION_LIST,
					    CFG_QCOM_MRC_REVOCATION_LIST);
}
