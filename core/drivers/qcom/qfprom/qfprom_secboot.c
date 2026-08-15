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

TEE_Result qcom_secboot_is_enabled(bool *enabled)
{
	struct qfprom_context *drv = qfprom_get_context();
	uint32_t val = 0;

	if (!enabled)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!drv->raw_base_va)
		return TEE_ERROR_BAD_STATE;

	val = io_read32(drv->raw_base_va + SECURE_BOOT_APPS_OFFSET);
	*enabled = (val & SECURE_BOOT_AUTH_EN_BMSK) != 0;

	return TEE_SUCCESS;
}

TEE_Result qcom_secboot_is_use_serial_num_enabled(bool *enabled)
{
	struct qfprom_context *drv = qfprom_get_context();
	uint32_t val = 0;

	if (!enabled)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!drv->raw_base_va)
		return TEE_ERROR_BAD_STATE;

	val = io_read32(drv->raw_base_va + SECURE_BOOT_APPS_OFFSET);
	*enabled = (val & SECURE_BOOT_USE_SERIAL_NUM_BMSK) != 0;

	return TEE_SUCCESS;
}

static TEE_Result read_sense_reg(uint32_t offset, uint32_t *out)
{
	struct qfprom_context *drv = qfprom_get_context();

	if (!drv->raw_base_va)
		return TEE_ERROR_BAD_STATE;

	*out = io_read32(drv->raw_base_va + offset);

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

		res = read_sense_reg(PK_HASH0_SENSE_OFFSET + off, &word);
		if (res)
			return res;

		memcpy(hash + off, &word, MIN(sizeof(word), len - off));
	}

	return TEE_SUCCESS;
}

TEE_Result qcom_secboot_get_device_ids(struct qcom_secboot_device_ids *ids)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t val = 0;

	if (!ids)
		return TEE_ERROR_BAD_PARAMETERS;

	res = read_sense_reg(OEM_ID_SENSE_OFFSET, &val);
	if (res)
		return res;
	ids->oem_id = (val & OEM_ID_BMSK) >> OEM_ID_SHFT;
	ids->model_id = (val & MODEL_ID_BMSK) >> MODEL_ID_SHFT;

	res = read_sense_reg(JTAG_ID_SENSE_OFFSET, &val);
	if (res)
		return res;
	ids->jtag_id = val & JTAG_ID_AUTH_BMSK;

	res = read_sense_reg(SERIAL_NUM_SENSE_OFFSET, &ids->serial_num);
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

TEE_Result qcom_secboot_get_soc_hw_version(uint32_t *fam_dev)
{
	vaddr_t va = 0;

	if (!fam_dev)
		return TEE_ERROR_BAD_PARAMETERS;

	va = (vaddr_t)phys_to_virt(TCSR_SOC_HW_VERSION_ADDR, MEM_AREA_IO_SEC,
				   sizeof(uint32_t));
	if (!va)
		return TEE_ERROR_GENERIC;

	*fam_dev = (io_read32(va) & SOC_HW_VERSION_FAM_DEV_BMSK) >>
		   SOC_HW_VERSION_FAM_DEV_SHFT;

	return TEE_SUCCESS;
}
