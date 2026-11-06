// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <trace.h>
#include <util.h>

#include "sec_elf_v2.h"
#include "sec_elf_v3.h"

TEE_Result sec_elf_v3_parse(const void *data, size_t len,
			    const struct secdat_v3_entry **entries,
			    uint32_t *num_entries)
{
	const struct secdat_v3_hdr *hdr = data;
	const struct secdat_v3_entry *e = NULL;
	size_t entries_size = 0;
	uint32_t n = 0;

	if (!data || !entries || !num_entries)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len < sizeof(*hdr)) {
		EMSG("Fuse list too small: %zu bytes", len);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->magic1 != SECDAT_MAGIC1 || hdr->magic2 != SECDAT_MAGIC2) {
		EMSG("Invalid fuse list magic: %#"PRIx32"/%#"PRIx32,
		     hdr->magic1, hdr->magic2);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (!hdr->num_entries ||
	    MUL_OVERFLOW(hdr->num_entries, sizeof(*e), &entries_size) ||
	    entries_size > len - sizeof(*hdr)) {
		EMSG("Invalid fuse list: %"PRIu32" entries in %zu bytes",
		     hdr->num_entries, len);
		return TEE_ERROR_BAD_FORMAT;
	}

	e = (const struct secdat_v3_entry *)(hdr + 1);
	for (n = 0; n < hdr->num_entries; n++) {
		if (e[n].region_type >= FUSEPROV_V3_REGION_TYPE_MAX) {
			EMSG("Invalid region %"PRIu32" in fuse entry %"PRIu32,
			     e[n].region_type, n);
			return TEE_ERROR_BAD_FORMAT;
		}
	}

	*entries = e;
	*num_entries = hdr->num_entries;

	return TEE_SUCCESS;
}
