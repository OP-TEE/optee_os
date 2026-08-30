// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <config.h>
#include <inttypes.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#include "qfprom_priv.h"
#include "qfprom_target.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TCSR_SOC_HW_VERSION_ADDR,
			CORE_MMU_PGDIR_SIZE);

static TEE_Result read_sense_reg(uint32_t offset, uint32_t *out)
{
	struct qfprom_context *drv = qfprom_get_context();

	if (!drv->raw_base)
		return TEE_ERROR_BAD_STATE;

	*out = io_read32(drv->raw_base + offset);

	return TEE_SUCCESS;
}

TEE_Result qcom_secboot_is_enabled(bool *enabled)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;

	if (!enabled)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_sense_reg(SECURE_BOOT_APPS_OFFSET, &val);
	if (res)
		return res;

	*enabled = (val & SECURE_BOOT_AUTH_EN_BMSK) != 0;

	return TEE_SUCCESS;
}

TEE_Result qcom_secboot_is_use_serial_num_enabled(bool *enabled)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;

	if (!enabled)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_sense_reg(SECURE_BOOT_APPS_OFFSET, &val);
	if (res)
		return res;

	*enabled = (val & SECURE_BOOT_USE_SERIAL_NUM_BMSK) != 0;

	return TEE_SUCCESS;
}

static TEE_Result read_pil_arb_en(bool *en)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };

	res = qfprom_read_row_locked(PIL_ARB_EN_RAW_ADDR,
				     QFPROM_ADDR_SPACE_CORR, row);
	if (res)
		return res;

	*en = (row[1] & PIL_ARB_EN_BMSK) != 0;

	return TEE_SUCCESS;
}

/*
 * Count set bits in @bitmask.
 * Cannot use __builtin_popcount(): OP-TEE core builds AArch64 with
 * -mgeneral-regs-only, so the compiler cannot inline the NEON sequence
 * and falls back to a libgcc call core does not link against.
 */
static uint32_t popcount32(uint32_t bitmask)
{
	uint32_t nb = 0;

	while (bitmask) {
		if (bitmask & 1)
			nb++;
		bitmask >>= 1;
	}

	return nb;
}

TEE_Result qcom_secboot_get_pil_rollback_version(uint32_t *version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	bool secboot = false;
	uint32_t lsb = 0;
	uint32_t msb = 0;
	bool en = false;

	if (!version)
		return TEE_ERROR_BAD_PARAMETERS;

	*version = 0;

	res = qcom_secboot_is_enabled(&secboot);
	if (res)
		return res;
	if (!secboot)
		return TEE_SUCCESS;

	res = read_pil_arb_en(&en);
	if (res)
		return res;
	if (!en)
		return TEE_SUCCESS;

	res = qfprom_target_read_pil_arb(&lsb, &msb);
	if (res)
		return res;

	*version = popcount32(lsb);
	if (PIL_ARB_MSB_ENABLED)
		*version += popcount32(msb);

	return TEE_SUCCESS;
}

TEE_Result qcom_secboot_blow_pil_rollback_version(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Result cleanup_res = TEE_SUCCESS;
	uint32_t cur_lsb = 0;
	uint32_t cur_msb = 0;
	bool secboot = false;
	uint32_t lsb_n = 0;
	uint32_t msb_n = 0;
	uint32_t cur = 0;
	bool en = false;

	res = qcom_secboot_is_enabled(&secboot);
	if (res)
		return res;
	if (!secboot)
		return TEE_SUCCESS;

	res = read_pil_arb_en(&en);
	if (res)
		return res;
	if (!en)
		return TEE_SUCCESS;

	res = qfprom_target_read_pil_arb(&cur_lsb, &cur_msb);
	if (res)
		return res;
	cur = popcount32(cur_lsb);
	if (PIL_ARB_MSB_ENABLED)
		cur += popcount32(cur_msb);

	if (version <= cur)
		return TEE_SUCCESS;

	res = qfprom_hw_init();
	if (res)
		return res;

	/* Saturate each word at its capacity, programming the LSB first. */
	lsb_n = MIN(version, (uint32_t)PIL_ARB_LSB_MAX_VERSION);
	res = qfprom_target_write_pil_arb_lsb(lsb_n);
	if (res)
		goto out;

	if (PIL_ARB_MSB_ENABLED && version > PIL_ARB_LSB_MAX_VERSION) {
		msb_n = MIN(version - PIL_ARB_LSB_MAX_VERSION,
			    (uint32_t)PIL_ARB_MSB_MAX_VERSION);
		res = qfprom_target_write_pil_arb_msb(msb_n);
	}

out:
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

TEE_Result qcom_secboot_get_root_of_trust(uint8_t *hash, size_t len)
{
	size_t off = 0;

	if (!hash)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len != QFPROM_ROOT_OF_TRUST_BYTE_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	for (off = 0; off < len; off += sizeof(uint32_t)) {
		TEE_Result res = TEE_ERROR_GENERIC;
		uint32_t word = 0;

		res = read_sense_reg(PK_HASH0_OFFSET + off, &word);
		if (res)
			return res;

		memcpy(hash + off, &word, sizeof(word));
	}

	return TEE_SUCCESS;
}

TEE_Result qcom_secboot_get_device_ids(struct qcom_secboot_device_ids *ids)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;

	if (!ids)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_sense_reg(OEM_ID_OFFSET, &val);
	if (res)
		return res;
	ids->oem_id = (val & OEM_ID_BMSK) >> OEM_ID_SHFT;
	ids->model_id = (val & MODEL_ID_BMSK) >> MODEL_ID_SHFT;

	res = read_sense_reg(JTAG_ID_OFFSET, &val);
	if (res)
		return res;
	ids->jtag_id = val & JTAG_ID_AUTH_BMSK;

	res = read_sense_reg(SERIAL_NUM_OFFSET, &ids->serial_num);
	if (res)
		return res;

	return TEE_SUCCESS;
}

#define SEGMENT_HASH_ROOT_CERT_SEL_MAX	3U

/*
 * Return the hash algorithm's digest size (SHA-256 or SHA-384) selected
 * for the root cert at @root_cert_sel, per the OEM_CONFIG2 fuse row.
 */
TEE_Result qcom_secboot_get_segment_hash_len(uint32_t root_cert_sel,
					     uint32_t *hash_len)
{
	if (!hash_len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (root_cert_sel > SEGMENT_HASH_ROOT_CERT_SEL_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED(CFG_QCOM_SEGMENT_HASH_SELECT)) {
		TEE_Result res = TEE_ERROR_GENERIC;
		uint32_t val = 0;

		res = read_sense_reg(OEM_CONFIG2_OFFSET, &val);
		if (res)
			return res;

		if (val & BIT32(SEGMENT_HASH_FUNCTION_SELECT0_SHFT +
				root_cert_sel))
			*hash_len = TEE_SHA256_HASH_SIZE;
		else
			*hash_len = TEE_SHA384_HASH_SIZE;
	} else {
		*hash_len = TEE_SHA384_HASH_SIZE;
	}

	return TEE_SUCCESS;
}

TEE_Result qcom_secboot_get_eku_enforcement_en(bool *enabled)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;

	if (!enabled)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_sense_reg(OEM_CONFIG2_OFFSET, &val);
	if (res)
		return res;

	*enabled = val & BIT32(EKU_ENFORCEMENT_EN_SHFT);

	return TEE_SUCCESS;
}

#define SECBOOT_MAX_NUM_ROOT_CERTS	4U

TEE_Result qcom_secboot_get_mrc_info(struct qcom_secboot_mrc_info *info)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t total = 0;
	uint32_t val = 0;

	if (!info)
		return TEE_ERROR_BAD_PARAMETERS;

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

	total = ((val & ROOT_CERT_TOTAL_NUM_BMSK) >> ROOT_CERT_TOTAL_NUM_SHFT) +
		1;
	if (total > SECBOOT_MAX_NUM_ROOT_CERTS)
		return TEE_ERROR_BAD_STATE;
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

TEE_Result qcom_secboot_get_soc_hw_version(uint32_t *fam_dev)
{
	static vaddr_t soc_hw_version_addr;
	uint32_t val = 0;

	if (!fam_dev)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!soc_hw_version_addr) {
		soc_hw_version_addr =
			(vaddr_t)phys_to_virt(TCSR_SOC_HW_VERSION_ADDR,
					      MEM_AREA_IO_SEC,
					      sizeof(uint32_t));
		if (!soc_hw_version_addr)
			return TEE_ERROR_GENERIC;
	}

	val = io_read32(soc_hw_version_addr);
	*fam_dev = (val & SOC_HW_VERSION_FAM_DEV_BMSK) >>
		   SOC_HW_VERSION_FAM_DEV_SHFT;

	return TEE_SUCCESS;
}
