// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "sec_elf_v3.h"

static TEE_Result check_random_rows(const struct fuse_entry *entries,
				    uint32_t count, uint32_t region)
{
	uint32_t rows = 0;
	uint32_t n = 0;

	for (n = 0; n < count; n++) {
		if (entries[n].region == region &&
		    entries[n].operation == SECDAT_V3_OP_BLOW_RANDOM)
			rows++;
	}

	if (rows > SECDAT_V3_MAX_RANDOM_ROWS) {
		EMSG("Too many random rows (%"PRIu32" > %u) in region %#"PRIx32,
		     rows, SECDAT_V3_MAX_RANDOM_ROWS, region);
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

TEE_Result sec_elf_v3_parse(const uint8_t *data, size_t len,
			    const struct fuse_entry **entries,
			    uint32_t *count)
{
	static const uint32_t random_regions[] = {
		SECDAT_V3_REGION_SEC_HW_KEY,
		SECDAT_V3_REGION_OEM_PRODUCT_SEED,
		SECDAT_V3_REGION_OEM_SPARE,
	};
	struct secdat_v3_hdr hdr = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t n = 0;

	if (!data || !len || !entries || !count)
		return TEE_ERROR_BAD_PARAMETERS;

	*entries = NULL;
	*count = 0;

	/* The buffer holds arbitrary data when there is no image */
	if (len < 2 * sizeof(uint32_t))
		return TEE_ERROR_ITEM_NOT_FOUND;
	memcpy(&hdr, data, MIN(len, sizeof(hdr)));
	if (hdr.magic1 != SECDAT_V3_MAGIC1 || hdr.magic2 != SECDAT_V3_MAGIC2) {
		DMSG("No fuse provisioning image present");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (len < sizeof(hdr)) {
		EMSG("Fuse data too small: %zu bytes", len);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr.revision != SECDAT_V3_REVISION) {
		EMSG("Unsupported fuse data revision: %#"PRIx32, hdr.revision);
		return TEE_ERROR_BAD_FORMAT;
	}

	if ((len - sizeof(hdr)) / sizeof(struct fuse_entry) <
	    hdr.num_entries) {
		EMSG("Fuse data too small for %"PRIu32" entries",
		     hdr.num_entries);
		return TEE_ERROR_BAD_FORMAT;
	}

	*entries = (const struct fuse_entry *)(data + sizeof(hdr));
	for (n = 0; n < ARRAY_SIZE(random_regions); n++) {
		res = check_random_rows(*entries, hdr.num_entries,
					random_regions[n]);
		if (res) {
			*entries = NULL;
			return res;
		}
	}

	*count = hdr.num_entries;
	return TEE_SUCCESS;
}
