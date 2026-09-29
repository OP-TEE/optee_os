// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <crypto/crypto.h>
#include <drivers/qcom/qfprom/qfprom.h>
#include <inttypes.h>
#include <kernel/panic.h>
#include <qfprom_target.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "sec_elf_v2.h"

static TEE_Result blow_fuse_region(enum fuseprov_region_type region,
				   const struct fuse_entry *entries,
				   uint32_t count, bool *fuses_blown)
{
	enum qfprom_error err = QFPROM_NO_ERR;
	uint32_t mask_fec_msb_bits = 0;
	uint32_t current_data[2] = {0};
	uint32_t fuse_data[2] = {0};
	uint8_t has_fec = 0;
	uint32_t i = 0;

	for (i = 0; i < count; i++) {
		const struct fuse_entry *entry = &entries[i];

		if (entry->region != region ||
		    entry->operation != FUSEPROV_OP_BLOW ||
		    (entry->lsb_val == 0 && entry->msb_val == 0))
			continue;

		err = qfprom_row_has_fec_bits(entry->addr,
					      QFPROM_ADDR_SPACE_RAW,
					      &has_fec);
		if (err != QFPROM_NO_ERR) {
			EMSG("Failed to check FEC for addr 0x%08"PRIx32
			     ": error=%d", entry->addr, err);
			return TEE_ERROR_GENERIC;
		}

		if (has_fec)
			mask_fec_msb_bits = 0x00FFFFFF;
		else
			mask_fec_msb_bits = 0xFFFFFFFF;

		err = qfprom_read_row(entry->addr, QFPROM_ADDR_SPACE_CORR,
				      current_data);
		if (err != QFPROM_NO_ERR) {
			EMSG("Failed to read fuse at 0x%08"PRIx32 ": error=%d",
			     entry->addr, err);
			return TEE_ERROR_GENERIC;
		}

		/* Check if fuse bits are already blown */
		if (((current_data[0] & entry->lsb_val) == entry->lsb_val) &&
		    ((current_data[1] & entry->msb_val) ==
		     (entry->msb_val & mask_fec_msb_bits))) {
			IMSG("Fuse at 0x%08"PRIx32 " already provisioned",
			     entry->addr);
			continue;
		}

		fuse_data[0] = entry->lsb_val;
		fuse_data[1] = entry->msb_val;

		err = qfprom_write_row(entry->addr, fuse_data);
		if (err != QFPROM_NO_ERR) {
			EMSG("Failed to write fuse at 0x%08"PRIx32 ": error=%d",
			     entry->addr, err);
			return TEE_ERROR_GENERIC;
		}

		if (fuses_blown)
			*fuses_blown = true;
	}

	return TEE_SUCCESS;
}

TEE_Result provision_execute(const uint8_t *data, size_t len,
			     bool *fuses_blown)
{
	const struct qfuse_list_hdr *qfuse_hdr = NULL;
	const struct segment_hdr *segments = NULL;
	const struct fuse_entry *entries = NULL;
	enum qfprom_error err = QFPROM_NO_ERR;
	const struct secdat_hdr *hdr = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *seg_data = NULL;
	uint32_t perm_data[2] = {0};
	bool any_blown = false;
	uint32_t seg_size = 0;
	uint32_t count = 0;

	if (!data || len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = sec_elf_parse(data, len, &hdr, &segments);
	if (res != TEE_SUCCESS)
		return res;

	res = sec_elf_validate_hash(data, len, hdr);
	if (res != TEE_SUCCESS)
		return res;

	res = qfprom_hw_init();
	if (res != TEE_SUCCESS) {
		EMSG("Failed to initialize QFPROM hardware: 0x%"PRIx32, res);
		return res;
	}

	err = qfprom_read_row(WRITE_PERMISSION_ADDR, QFPROM_ADDR_SPACE_CORR,
			      perm_data);
	if (err != QFPROM_NO_ERR) {
		EMSG("Failed to read WRITE_PERMISSION fuse: error=%d", err);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	if (perm_data[0] & OEM_SECURE_BOOT_PERM_MASK) {
		res = TEE_ERROR_ACCESS_DENIED;
		goto out;
	}

	res = sec_elf_find_segment(data, len,
				   SECDAT_SEGMENT_TYPE_EFUSE,
				   &seg_data, &seg_size);

	if (res != TEE_SUCCESS) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (!seg_data) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (seg_size < sizeof(struct qfuse_list_hdr)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	qfuse_hdr = (const struct qfuse_list_hdr *)seg_data;
	count = qfuse_hdr->fuse_count;
	entries = (const struct fuse_entry *)
		  (seg_data + sizeof(struct qfuse_list_hdr));

	res = blow_fuse_region(FUSEPROV_REGION_GENERAL, entries, count,
			       &any_blown);
	if (res != TEE_SUCCESS)
		goto out;

	res = provision_shk(entries, count, &any_blown);
	if (res != TEE_SUCCESS)
		goto out;

	res = provision_oem_spare(entries, count, &any_blown);
	if (res != TEE_SUCCESS)
		goto out;

	res = blow_fuse_region(FUSEPROV_REGION_OEM_CONFIG, entries, count,
			       &any_blown);
	if (res != TEE_SUCCESS)
		goto out;

	res = blow_fuse_region(FUSEPROV_REGION_SECBOOT, entries, count,
			       &any_blown);
	if (res != TEE_SUCCESS)
		goto out;

	res = blow_fuse_region(FUSEPROV_REGION_FEC_EN, entries, count,
			       &any_blown);
	if (res != TEE_SUCCESS)
		goto out;

	res = blow_fuse_region(FUSEPROV_REGION_RW_PERM, entries, count,
			       &any_blown);
	if (res != TEE_SUCCESS)
		goto out;

	if (fuses_blown)
		*fuses_blown = any_blown;

	res = TEE_SUCCESS;

out:
	qfprom_hw_deinit();
	return res;
}

void provision_reset_device(void)
{
	IMSG("Fuse provisioning complete - manual reset required from U-Boot");
}
