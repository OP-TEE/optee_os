// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <trace.h>
#include <util.h>

#include "provision.h"
#include "sec_elf_v2.h"

static_assert(FUSEPROV_OP_BLOW == PROVISION_OP_BLOW);

static enum provision_category v2_category(uint32_t region)
{
	switch (region) {
	case FUSEPROV_REGION_SECBOOT:
		return PROV_CAT_SECBOOT;
	case FUSEPROV_REGION_SHK:
		return PROV_CAT_SHK;
	case FUSEPROV_REGION_OEM_CONFIG:
		return PROV_CAT_OEM_CONFIG;
	case FUSEPROV_REGION_RW_PERM:
		return PROV_CAT_RW_PERM;
	case FUSEPROV_REGION_FEC_EN:
		return PROV_CAT_FEC_EN;
	default:
		/* The remaining valid regions are programmed with GENERAL */
		return region < FUSEPROV_REGION_MAX ? PROV_CAT_GENERAL :
						      PROV_CAT_NONE;
	}
}

static TEE_Result v2_row_has_fec(const struct provision_backend *be,
				 const struct fuse_entry *entry,
				 bool *has_fec)
{
	return be->row_has_fec(entry->addr, has_fec);
}

static bool v2_row_programmed(const uint32_t cur[2],
			      const struct fuse_entry *entry, bool has_fec)
{
	uint32_t mask_fec_msb_bits = has_fec ? 0x00FFFFFF : 0xFFFFFFFF;

	return ((cur[0] & entry->lsb_val) == entry->lsb_val) &&
	       ((cur[1] & entry->msb_val) ==
		(entry->msb_val & mask_fec_msb_bits));
}

static void v2_row_value(const struct fuse_entry *entry, bool has_fec __unused,
			 uint32_t data[2])
{
	data[0] = entry->lsb_val;
	data[1] = entry->msb_val;
}

/* GENERAL, SHK and SPARE come first, the permission groups last */
static const struct provision_pass v2_passes[] = {
	{ provision_blow_category, PROV_CAT_GENERAL },
	{ provision_shk },
	{ provision_oem_spare },
	{ provision_blow_category, PROV_CAT_OEM_CONFIG },
	{ provision_blow_category, PROV_CAT_SECBOOT },
	{ provision_blow_category, PROV_CAT_FEC_EN },
	{ provision_blow_category, PROV_CAT_RW_PERM },
};

static const struct provision_policy sec_elf_v2_policy = {
	.category = v2_category,
	.row_has_fec = v2_row_has_fec,
	.row_programmed = v2_row_programmed,
	.row_value = v2_row_value,
	.passes = v2_passes,
	.num_passes = ARRAY_SIZE(v2_passes),
};

TEE_Result provision_execute(const uint8_t *data, size_t len,
			     bool *fuses_blown)
{
	const struct provision_backend *be = &provision_backend_qfprom;
	const struct qfuse_list_hdr *qfuse_hdr = NULL;
	const struct segment_hdr *segments = NULL;
	const struct fuse_entry *entries = NULL;
	const struct secdat_hdr *hdr = NULL;
	bool secboot_write_disabled = false;
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *seg_data = NULL;
	uint32_t seg_size = 0;
	uint32_t count = 0;

	if (fuses_blown)
		*fuses_blown = false;

	if (!data || len < sizeof(*hdr))
		return TEE_ERROR_BAD_PARAMETERS;

	res = be->is_write_locked(&secboot_write_disabled);
	if (res != TEE_SUCCESS)
		return res;
	if (secboot_write_disabled) {
		IMSG("Fuse provisioning already locked");
		return TEE_SUCCESS;
	}

	hdr = (const struct secdat_hdr *)data;
	if (hdr->magic1 != SECDAT_MAGIC1 || hdr->magic2 != SECDAT_MAGIC2) {
		DMSG("No fuse provisioning image present");
		return TEE_SUCCESS;
	}

	res = sec_elf_parse(data, len, &hdr, &segments);
	if (res != TEE_SUCCESS)
		return res;

	res = sec_elf_validate_hash(data, len, hdr);
	if (res != TEE_SUCCESS)
		return res;

	res = sec_elf_find_segment(data, len,
				   SECDAT_SEGMENT_TYPE_EFUSE,
				   &seg_data, &seg_size);

	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return TEE_SUCCESS;
	if (res)
		return res;

	qfuse_hdr = (const struct qfuse_list_hdr *)seg_data;
	count = qfuse_hdr->fuse_count;
	entries = (const struct fuse_entry *)
		  (seg_data + sizeof(struct qfuse_list_hdr));

	return provision_run(be, &sec_elf_v2_policy, entries, count,
			     fuses_blown);
}
