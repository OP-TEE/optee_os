// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <crypto/crypto.h>
#include <drivers/qcom/qfprom/qfprom.h>
#include <inttypes.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

#include "provision.h"
#include "sec_elf_v3.h"

#define V3_RANDOM_ROW_BYTES	8
#define V3_RANDOM_BYTES		\
	(SECDAT_V3_MAX_RANDOM_ROWS * V3_RANDOM_ROW_BYTES)

/*
 * FEC bits of a row live in bits [62:56] of its MSB word. Keep the data bits
 * (and bit 31) of the value before inserting the computed FEC.
 */
#define V3_MSB_DATA_MASK	0x80FFFFFFU
/* Bits of the MSB word that are not FEC when the row has FEC */
#define V3_MSB_NO_FEC_MASK	0x00FFFFFFU

/*
 * Regions that are not listed are programmed with GENERAL: OEM_PK_HASH,
 * ANTI_ROLLBACK, IMAGE_ENCR_KEY and MRC_2_0 among them.
 */
static enum provision_category v3_category(uint32_t region)
{
	switch (region) {
	case SECDAT_V3_REGION_OEM_SEC_BOOT:
		return PROV_CAT_SECBOOT;
	case SECDAT_V3_REGION_SEC_HW_KEY:
		return PROV_CAT_SHK;
	case SECDAT_V3_REGION_OEM_CONFIG:
		return PROV_CAT_OEM_CONFIG;
	case SECDAT_V3_REGION_READ_PERM:
		return PROV_CAT_READ_PERM;
	case SECDAT_V3_REGION_WRITE_PERM:
		return PROV_CAT_WRITE_PERM;
	case SECDAT_V3_REGION_FEC_EN:
		return PROV_CAT_FEC_EN;
	case SECDAT_V3_REGION_OEM_PRODUCT_SEED:
		return PROV_CAT_PRODUCT_SEED;
	case SECDAT_V3_REGION_OEM_SPARE:
		return PROV_CAT_OEM_SPARE;
	default:
		return PROV_CAT_GENERAL;
	}
}

/* The rows with FEC are known from the region, not from the address */
static TEE_Result v3_row_has_fec(const struct provision_backend *be __unused,
				 const struct fuse_entry *entry,
				 bool *has_fec)
{
	*has_fec = entry->region == SECDAT_V3_REGION_OEM_PK_HASH ||
		   entry->region == SECDAT_V3_REGION_OEM_PRODUCT_SEED;

	return TEE_SUCCESS;
}

/* The FEC bits of the current value are not compared */
static bool v3_row_programmed(const uint32_t cur[2],
			      const struct fuse_entry *entry, bool has_fec)
{
	uint32_t mask = has_fec ? V3_MSB_NO_FEC_MASK : UINT32_MAX;

	return (cur[0] & entry->lsb_val) == entry->lsb_val &&
	       (cur[1] & entry->msb_val & mask) == (entry->msb_val & mask);
}

static void v3_fec_value(bool has_fec, uint32_t data[2])
{
	if (has_fec)
		data[1] = qfprom_fec_63_56_bit(data[0],
					       data[1] & V3_MSB_DATA_MASK);
}

static void v3_row_value(const struct fuse_entry *entry, bool has_fec,
			 uint32_t data[2])
{
	data[0] = entry->lsb_val;
	data[1] = entry->msb_val;
	v3_fec_value(has_fec, data);
}

static bool is_random_row(const struct provision_policy *pol,
			  enum provision_category category,
			  const struct fuse_entry *entry)
{
	return pol->category(entry->region) == category &&
	       entry->operation == SECDAT_V3_OP_BLOW_RANDOM;
}

/*
 * Program the BLOW_RANDOM rows of @category with random data. The n-th random
 * row of the category always gets the n-th group of random bytes, also when
 * an earlier row was already programmed and is left alone.
 */
static TEE_Result v3_blow_random(const struct provision_backend *be,
				 const struct provision_policy *pol,
				 enum provision_category category,
				 const struct fuse_entry *entries,
				 uint32_t count, bool *fuses_blown)
{
	uint8_t random[V3_RANDOM_BYTES] = { };
	TEE_Result res = TEE_SUCCESS;
	uint32_t data[2] = { };
	uint32_t rows = 0;
	uint32_t n = 0;
	uint32_t i = 0;

	for (i = 0; i < count; i++)
		if (is_random_row(pol, category, &entries[i]))
			rows++;
	if (!rows)
		return TEE_SUCCESS;

	if (rows > SECDAT_V3_MAX_RANDOM_ROWS)
		return TEE_ERROR_BAD_FORMAT;

	res = crypto_rng_read(random, sizeof(random));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to generate random data: %#"PRIx32, res);
		goto out;
	}

	for (i = 0; i < count; i++) {
		const struct fuse_entry *entry = &entries[i];
		bool has_fec = false;

		if (!is_random_row(pol, category, entry))
			continue;

		res = be->read_row(entry->addr, data);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to read fuse at 0x%08"PRIx32
			     ": error=%#"PRIx32, entry->addr, res);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		if (data[0] || data[1]) {
			IMSG("Fuse at 0x%08"PRIx32" already provisioned",
			     entry->addr);
			n++;
			continue;
		}

		memcpy(data, random + n * V3_RANDOM_ROW_BYTES,
		       V3_RANDOM_ROW_BYTES);
		n++;

		res = pol->row_has_fec(be, entry, &has_fec);
		if (res != TEE_SUCCESS)
			goto out;
		v3_fec_value(has_fec, data);

		res = be->write_row(entry->addr, data);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to write fuse at 0x%08"PRIx32
			     ": error=%#"PRIx32, entry->addr, res);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		if (fuses_blown)
			*fuses_blown = true;
	}

out:
	memzero_explicit(random, sizeof(random));
	memzero_explicit(data, sizeof(data));
	return res;
}

/*
 * The write-permission rows come last as they lock further writes. The SHK,
 * product seed and OEM spare regions are only programmed with random data:
 * a BLOW entry of one of them is ignored.
 */
static const struct provision_pass v3_passes[] = {
	{ provision_blow_category, PROV_CAT_GENERAL },
	{ v3_blow_random, PROV_CAT_SHK },
	{ v3_blow_random, PROV_CAT_PRODUCT_SEED },
	{ v3_blow_random, PROV_CAT_OEM_SPARE },
	{ provision_blow_category, PROV_CAT_OEM_CONFIG },
	{ provision_blow_category, PROV_CAT_SECBOOT },
	{ provision_blow_category, PROV_CAT_FEC_EN },
	{ provision_blow_category, PROV_CAT_READ_PERM },
	{ provision_blow_category, PROV_CAT_WRITE_PERM },
};

static const struct provision_policy sec_elf_v3_policy = {
	.category = v3_category,
	.row_has_fec = v3_row_has_fec,
	.row_programmed = v3_row_programmed,
	.row_value = v3_row_value,
	.passes = v3_passes,
	.num_passes = ARRAY_SIZE(v3_passes),
};

TEE_Result provision_execute_v3(const struct provision_backend *be,
				const uint8_t *data, size_t len,
				bool *fuses_blown)
{
	const struct fuse_entry *entries = NULL;
	bool locked = false;
	uint32_t count = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (fuses_blown)
		*fuses_blown = false;

	res = sec_elf_v3_parse(data, len, &entries, &count);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		return TEE_SUCCESS;
	if (res != TEE_SUCCESS)
		return res;

	if (be->is_write_locked) {
		res = be->is_write_locked(&locked);
		if (res != TEE_SUCCESS)
			return res;
		if (locked) {
			IMSG("Fuse provisioning already locked");
			return TEE_SUCCESS;
		}
	}

	return provision_run(be, &sec_elf_v3_policy, entries, count,
			     fuses_blown);
}
