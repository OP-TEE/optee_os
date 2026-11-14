// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/qcom/qfprom/qfprom.h>
#include <inttypes.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdlib.h>
#include <stdlib_ext.h>
#include <string.h>
#include <string_ext.h>
#include <tmefuse_client.h>
#include <tmel_auth.h>
#include <trace.h>
#include <util.h>

#include "fuseprov_v3.h"
#include "sec_elf_v3.h"

/* Rows whose MSB word carries FEC bits, as inclusive address ranges */
static const struct mem_region fec_enabled_ranges[] =
	QCOM_FEC_ENABLED_RANGES;

/*
 * Region groups in the order they are blown, which must not change. The
 * OEM product seed is special: see blow_oem_product_seed_region().
 */
static const uint32_t blow_order[] = {
	BIT32(FUSEPROV_V3_REGION_TYPE_OEM_SEC_BOOT) |
	BIT32(FUSEPROV_V3_REGION_TYPE_ANTI_ROLLBACK) |
	BIT32(FUSEPROV_V3_REGION_TYPE_IMAGE_ENCR_KEY) |
	BIT32(FUSEPROV_V3_REGION_TYPE_MRC_2_0) |
	BIT32(FUSEPROV_V3_REGION_TYPE_TME_SPARE),
	BIT32(FUSEPROV_V3_REGION_TYPE_SEC_HW_KEY),
	BIT32(FUSEPROV_V3_REGION_TYPE_OEM_PRODUCT_SEED),
	BIT32(FUSEPROV_V3_REGION_TYPE_OEM_SPARE),
	BIT32(FUSEPROV_V3_REGION_TYPE_OEM_CONFIG),
	BIT32(FUSEPROV_V3_REGION_TYPE_OEM_PK_HASH),
	BIT32(FUSEPROV_V3_REGION_TYPE_FEC_EN),
	BIT32(FUSEPROV_V3_REGION_TYPE_READ_PERM),
	BIT32(FUSEPROV_V3_REGION_TYPE_WRITE_PERM),
	BIT32(FUSEPROV_V3_REGION_TYPE_TME_OEM),
	BIT32(FUSEPROV_V3_REGION_TYPE_TME_FEC_EN),
	BIT32(FUSEPROV_V3_REGION_TYPE_TME_RW_PERM),
};

static bool is_fec_enabled_for_row(uint32_t row_addr)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(fec_enabled_ranges); i++) {
		if (row_addr >= fec_enabled_ranges[i].start_addr &&
		    row_addr <= fec_enabled_ranges[i].end_addr)
			return true;
	}

	return false;
}

static TEE_Result blow_tme_oem_mrc_row(const struct secdat_v3_entry *e)
{
	uint32_t act_vector = e->lsb_val & TME_OEM_MRC_VECTOR_MASK;
	uint32_t rev_vector = (e->lsb_val >> QCOM_TME_OEM_MRC_VECTOR_BITS) &
			      TME_OEM_MRC_VECTOR_MASK;

	/* Fold the hybrid PQC bits into the activation vector's top bits */
	act_vector |= (e->msb_val &
		       QCOM_TME_OEM_MRC_HYBRID_STATE_VECTOR_MASK) <<
		      QCOM_TME_OEM_MRC_ACTIVATION_HYBRID_SHIFT;

	return tme_oem_mrc_state_update(act_vector, rev_vector);
}

static TEE_Result blow_fuse_row(const struct secdat_v3_entry *e)
{
	struct tme_fuse_payload fuse = { .fuse_addr = e->fuse_addr,
					 .lsb_val = e->lsb_val,
					 .msb_val = e->msb_val };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (e->fuse_addr == QCOM_TME_OEM_MRC_STATE_VECTOR_ADDR)
		return blow_tme_oem_mrc_row(e);

	if (is_fec_enabled_for_row(e->fuse_addr)) {
		fuse.msb_val &= FEC_MSB_DATA_MASK;
		fuse.msb_val = qfprom_fec_63_56_bit(fuse.lsb_val, fuse.msb_val);
	}

	res = tme_fuse_write_row(&fuse);
	memzero_explicit(&fuse, sizeof(fuse));

	return res;
}

/* The OEM product seed is written as a whole: TME-Lite refuses single rows */
static TEE_Result
blow_oem_product_seed_region(const struct secdat_v3_entry *entries,
			     uint32_t num_entries)
{
	struct tme_fuse_payload fuse_rows[OEM_PRODUCT_SEED_ROWS] = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t row_count = 0;
	uint32_t i = 0;

	for (i = 0; i < num_entries; i++) {
		if (entries[i].region_type !=
		    FUSEPROV_V3_REGION_TYPE_OEM_PRODUCT_SEED)
			continue;

		if (row_count == OEM_PRODUCT_SEED_ROWS) {
			EMSG("OEM product seed: too many entries");
			res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}

		fuse_rows[row_count].fuse_addr = entries[i].fuse_addr;
		fuse_rows[row_count].lsb_val = entries[i].lsb_val;
		fuse_rows[row_count].msb_val = entries[i].msb_val;
		row_count++;
	}

	if (!row_count) {
		res = TEE_SUCCESS;
		goto out;
	}

	if (row_count != OEM_PRODUCT_SEED_ROWS) {
		EMSG("OEM product seed needs %d entries, got %"PRIu32,
		     OEM_PRODUCT_SEED_ROWS, row_count);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	res = tme_fuse_write_multiple_rows(fuse_rows, row_count);

out:
	memzero_explicit(fuse_rows, sizeof(fuse_rows));
	return res;
}

static TEE_Result blow_fuse_region(uint32_t regions,
				   const struct secdat_v3_entry *entries,
				   uint32_t num_entries)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t i = 0;

	if (regions & BIT32(FUSEPROV_V3_REGION_TYPE_OEM_PRODUCT_SEED))
		return blow_oem_product_seed_region(entries, num_entries);

	for (i = 0; i < num_entries; i++) {
		if (!(regions & BIT32(entries[i].region_type)))
			continue;

		/* Skip all-zero rows */
		if (!entries[i].lsb_val && !entries[i].msb_val)
			continue;

		res = blow_fuse_row(&entries[i]);
		if (res) {
			EMSG("Failed to blow fuse row %#"PRIx32": %#"PRIx32,
			     entries[i].fuse_addr, res);
			return res;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result copy_from_nsec(void *dst, paddr_t pa, size_t len)
{
	void *va = NULL;

	if (!core_pbuf_is(CORE_MEM_NON_SEC, pa, len)) {
		EMSG("Fuse list %#"PRIxPA"/%zu is not in non-secure memory",
		     pa, len);
		return TEE_ERROR_SECURITY;
	}

	va = core_mmu_add_mapping(MEM_AREA_RAM_NSEC, pa, len);
	if (!va) {
		EMSG("Failed to map fuse list %#"PRIxPA"/%zu", pa, len);
		return TEE_ERROR_GENERIC;
	}

	dcache_inv_range(va, len);
	memcpy(dst, va, len);

	if (core_mmu_remove_mapping(MEM_AREA_RAM_NSEC, va, len))
		EMSG("Failed to unmap fuse list");

	return TEE_SUCCESS;
}

/* @blk, at @blk_pa, holds [ELF metadata][region list][fuse list] */
static TEE_Result secure_authenticate(void *blk, paddr_t blk_pa, size_t elf_len,
				      size_t regions_off, size_t secdat_off,
				      size_t secdat_len, size_t total)
{
	struct tmel_sec_auth_params auth = { };
	struct mem_region region = {
		.start_addr = (uint32_t)(blk_pa + secdat_off),
		.end_addr = (uint32_t)(blk_pa + secdat_off + secdat_len),
	};

	memcpy((uint8_t *)blk + regions_off, &region, sizeof(region));
	/* TME-Lite reads memory directly, not through our cache */
	dcache_clean_range(blk, total);

	auth.sw_id = SECELF_SW_ID;
	auth.elf_buf.pa = blk_pa;
	auth.elf_buf.len = elf_len;
	auth.region_list.pa = blk_pa + regions_off;
	auth.region_list.len = sizeof(region);
	auth.relocate = 1;
	auth.flags = TMEL_AUTH_FLAG_NS_INTEGRITY;

	return tmel_secure_auth(&auth);
}

TEE_Result fuseprov_v3_blow_secelf(const void *elf, size_t elf_len,
				   paddr_t secdat_pa, size_t secdat_len)
{
	const struct secdat_v3_entry *entries = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t num_entries = 0;
	size_t regions_off = 0;
	size_t secdat_off = 0;
	uint8_t *blk = NULL;
	paddr_t blk_pa = 0;
	size_t total = 0;
	size_t i = 0;

	if (!elf || !elf_len || !secdat_len)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Authenticate and parse the same secure copy: the non-secure
	 * originals could change after the check.
	 */
	if (ROUNDUP_OVERFLOW(elf_len, sizeof(uint64_t), &regions_off) ||
	    ADD_OVERFLOW(regions_off,
			 ROUNDUP(sizeof(struct mem_region), sizeof(uint64_t)),
			 &secdat_off) ||
	    ADD_OVERFLOW(secdat_off, secdat_len, &total))
		return TEE_ERROR_BAD_PARAMETERS;

	blk = malloc(total);
	if (!blk)
		return TEE_ERROR_OUT_OF_MEMORY;

	blk_pa = virt_to_phys(blk);
	/* TME-Lite takes 32-bit addresses, the exclusive end included */
	if (!blk_pa || (uint64_t)blk_pa + total >= BIT64(32)) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	dcache_inv_range((void *)elf, elf_len);
	memcpy(blk, elf, elf_len);

	res = copy_from_nsec(blk + secdat_off, secdat_pa, secdat_len);
	if (res)
		goto out;

	res = secure_authenticate(blk, blk_pa, elf_len, regions_off,
				  secdat_off, secdat_len, total);
	if (res) {
		EMSG("sec.elf authentication failed: %#"PRIx32, res);
		goto out;
	}

	res = sec_elf_v3_parse(blk + secdat_off, secdat_len, &entries,
			       &num_entries);
	if (res)
		goto out;

	for (i = 0; i < ARRAY_SIZE(blow_order); i++) {
		res = blow_fuse_region(blow_order[i], entries, num_entries);
		if (res)
			goto out;
	}

	IMSG("Fuse provisioning completed");

out:
	free_wipe(blk);
	return res;
}
