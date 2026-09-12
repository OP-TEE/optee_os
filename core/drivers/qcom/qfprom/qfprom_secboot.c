// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <config.h>
#include <initcall.h>
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

	if (!drv->raw_base_va)
		return TEE_ERROR_BAD_STATE;

	*out = io_read32(drv->raw_base_va + offset);

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

static TEE_Result read_corr_reg(uint32_t offset, uint32_t *out)
{
	struct qfprom_context *drv = qfprom_get_context();

	if (!drv->corr_base_va)
		return TEE_ERROR_BAD_STATE;

	*out = io_read32(drv->corr_base_va + offset);

	return TEE_SUCCESS;
}

static TEE_Result write_sense_reg(uint32_t offset, uint32_t val)
{
	struct qfprom_context *drv = qfprom_get_context();

	if (!drv->raw_base_va)
		return TEE_ERROR_BAD_STATE;

	io_write32(drv->raw_base_va + offset, val);

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
	uint32_t en = 0;

	if (!version)
		return TEE_ERROR_BAD_PARAMETERS;

	*version = 0;

	res = qcom_secboot_is_enabled(&secboot);
	if (res)
		return res;
	if (!secboot)
		return TEE_SUCCESS;

	res = read_corr_reg(PIL_ARB_EN_OFFSET, &en);
	if (res)
		return res;
	if (!(en & PIL_ARB_EN_BMSK))
		return TEE_SUCCESS;

	res = read_corr_reg(PIL_ARB_LSB_OFFSET, &lsb);
	if (res)
		return res;

	*version = popcount32(lsb & PIL_ARB_LSB_BMSK);

	if (PIL_ARB_MSB_ENABLED) {
		res = read_corr_reg(PIL_ARB_MSB_OFFSET, &msb);
		if (res)
			return res;
		*version += popcount32(msb & PIL_ARB_MSB_BMSK);
	}

	return TEE_SUCCESS;
}

static uint32_t unary_mask(uint32_t n)
{
	if (n >= 32)
		return 0xffffffffu;
	if (!n)
		return 0;
	return GENMASK_32(n - 1, 0);
}

TEE_Result qcom_secboot_blow_pil_rollback_version(uint32_t version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };
	uint32_t cur_lsb = 0;
	uint32_t cur_msb = 0;
	bool secboot = false;
	uint32_t lsb_n = 0;
	uint32_t msb_n = 0;
	uint32_t cur = 0;
	uint32_t en = 0;

	res = qcom_secboot_is_enabled(&secboot);
	if (res)
		return res;
	if (!secboot)
		return TEE_SUCCESS;

	res = read_corr_reg(PIL_ARB_EN_OFFSET, &en);
	if (res)
		return res;
	if (!(en & PIL_ARB_EN_BMSK))
		return TEE_SUCCESS;

	res = read_corr_reg(PIL_ARB_LSB_OFFSET, &cur_lsb);
	if (res)
		return res;
	cur = popcount32(cur_lsb & PIL_ARB_LSB_BMSK);
	if (PIL_ARB_MSB_ENABLED) {
		res = read_corr_reg(PIL_ARB_MSB_OFFSET, &cur_msb);
		if (res)
			return res;
		cur += popcount32(cur_msb & PIL_ARB_MSB_BMSK);
	}

	if (version <= cur)
		return TEE_SUCCESS;

	if (version > PIL_ARB_LSB_MAX_VERSION + PIL_ARB_MSB_MAX_VERSION) {
		EMSG("PAS ARB: version %#"PRIx32" exceeds fuse capacity",
		     version);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* qfprom_write_row() only blows 0->1 bits; OR in current contents. */
	lsb_n = MIN(version, (uint32_t)PIL_ARB_LSB_MAX_VERSION);
	if (version > PIL_ARB_LSB_MAX_VERSION)
		msb_n = version - PIL_ARB_LSB_MAX_VERSION;

	row[0] = (cur_lsb & PIL_ARB_LSB_BMSK) | unary_mask(lsb_n);
	row[1] = (cur_msb & PIL_ARB_MSB_BMSK) | unary_mask(msb_n);

	res = qfprom_hw_init();
	if (res)
		return res;

	res = qfprom_write_row(PIL_ARB_RAW_ADDR, row);
	qfprom_hw_deinit();
	if (res) {
		EMSG("PAS ARB: fuse write failed: %#"PRIx32, res);
		return res;
	}

	DMSG("PAS ARB: advanced device version %#"PRIx32" -> %#"PRIx32, cur,
	     version);

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

TEE_Result qcom_secboot_get_mrc_info(bool *root_sel_enabled,
				     uint32_t *num_roots,
				     uint32_t *activation_list,
				     uint32_t *revocation_list)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t total = 0;
	uint32_t val = 0;

	if (!root_sel_enabled || !num_roots || !activation_list ||
	    !revocation_list)
		return TEE_ERROR_BAD_PARAMETERS;

	*root_sel_enabled = false;
	*num_roots = 1;
	*activation_list = 0;
	*revocation_list = 0;

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
	*activation_list = val & MRC_ROOT_CERT_LIST_BMSK;

	res = read_sense_reg(MRC_REVOCATION_LIST_OFFSET, &val);
	if (res)
		return res;
	*revocation_list = val & MRC_ROOT_CERT_LIST_BMSK;

	*num_roots = total;
	*root_sel_enabled = true;

	return TEE_SUCCESS;
}

#ifdef CFG_QCOM_PAS_AUTH
/*
 * The MRC row is write-protected once the sticky bit is set, so skip
 * straight to the sticky-bit check rather than attempting (and expecting
 * to fail) a write on every normal boot.
 */
static TEE_Result qcom_secboot_blow_mrc_fuses(uint32_t activation_list,
					      uint32_t revocation_list)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row[2] = { };
	uint32_t sticky = 0;

	if (activation_list & ~MRC_ROOT_CERT_LIST_BMSK ||
	    revocation_list & ~MRC_ROOT_CERT_LIST_BMSK) {
		EMSG("MRC: activation/revocation list out of range: %#"PRIx32
		     "/%#"PRIx32, activation_list, revocation_list);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = read_sense_reg(MRC_STICKY_BIT_OFFSET, &sticky);
	if (res)
		return res;

	if (sticky & MRC_STICKY_BIT_BMSK) {
		DMSG("MRC: fuse row locked for this boot, skipping");
		return TEE_SUCCESS;
	}

	res = qfprom_hw_init();
	if (res)
		return res;

	/* Antifuse writes only set bits; safe to write the bitmap directly. */
	row[0] = activation_list;
	res = qfprom_write_row(MRC_ACTIVATION_LIST_RAW_ADDR, row);
	if (res) {
		DMSG("MRC: activation list fuse write failed: %#"PRIx32, res);
		goto out;
	}

	row[0] = revocation_list;
	res = qfprom_write_row(MRC_REVOCATION_LIST_RAW_ADDR, row);
	if (res) {
		DMSG("MRC: revocation list fuse write failed: %#"PRIx32, res);
		goto out;
	}

	res = write_sense_reg(MRC_STICKY_BIT_OFFSET, MRC_STICKY_BIT_BMSK);
	if (res)
		EMSG("MRC: failed to set sticky bit: %#"PRIx32, res);

out:
	qfprom_hw_deinit();
	return res;
}

static TEE_Result qcom_secboot_provision_mrc_fuses(void)
{
	if (!CFG_QCOM_MRC_ACTIVATION_LIST && !CFG_QCOM_MRC_REVOCATION_LIST)
		return TEE_SUCCESS;

	return qcom_secboot_blow_mrc_fuses(CFG_QCOM_MRC_ACTIVATION_LIST,
					    CFG_QCOM_MRC_REVOCATION_LIST);
}
driver_init(qcom_secboot_provision_mrc_fuses);
#endif /* CFG_QCOM_PAS_AUTH */

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
