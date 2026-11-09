// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <kernel/panic.h>
#include <string.h>
#include <string_ext.h>
#include <trace.h>
#include <util.h>

#include "provision.h"

TEE_Result provision_blow_category(const struct provision_backend *be,
				   const struct provision_policy *pol,
				   enum provision_category category,
				   const struct fuse_entry *entries,
				   uint32_t count, bool *fuses_blown)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t current_data[2] = {0};
	uint32_t fuse_data[2] = {0};
	bool has_fec = false;
	uint32_t i = 0;

	for (i = 0; i < count; i++) {
		const struct fuse_entry *entry = &entries[i];

		if (pol->category(entry->region) != category ||
		    entry->operation != PROVISION_OP_BLOW ||
		    (entry->lsb_val == 0 && entry->msb_val == 0))
			continue;

		res = pol->row_has_fec(be, entry, &has_fec);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to check FEC for addr 0x%08"PRIx32
			     ": error=%#"PRIx32, entry->addr, res);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		res = be->read_row(entry->addr, current_data);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to read fuse at 0x%08"PRIx32
			     ": error=%#"PRIx32, entry->addr, res);
			res = TEE_ERROR_GENERIC;
			goto out;
		}

		/* Check if fuse bits are already blown */
		if (pol->row_programmed(current_data, entry, has_fec)) {
			IMSG("Fuse at 0x%08"PRIx32 " already provisioned",
			     entry->addr);
			continue;
		}

		pol->row_value(entry, has_fec, fuse_data);

		res = be->write_row(entry->addr, fuse_data);
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
	memzero_explicit(current_data, sizeof(current_data));
	memzero_explicit(fuse_data, sizeof(fuse_data));
	return res;
}

TEE_Result provision_run(const struct provision_backend *be,
			 const struct provision_policy *pol,
			 const struct fuse_entry *entries, uint32_t count,
			 bool *fuses_blown)
{
	TEE_Result cleanup_res = TEE_SUCCESS;
	TEE_Result res = TEE_ERROR_GENERIC;
	bool any_blown = false;
	size_t n = 0;

	res = be->begin();
	if (res != TEE_SUCCESS) {
		EMSG("Failed to initialize the fuse backend: 0x%"PRIx32, res);
		return res;
	}

	for (n = 0; n < pol->num_passes; n++) {
		const struct provision_pass *pass = &pol->passes[n];

		res = pass->fn(be, pol, pass->category, entries, count,
			       &any_blown);
		if (res != TEE_SUCCESS)
			break;
	}

	if (fuses_blown)
		*fuses_blown = any_blown;
	cleanup_res = be->end();
	return res != TEE_SUCCESS ? res : cleanup_res;
}

void provision_reset_device(void)
{
	IMSG("Fuse provisioning complete - manual reset required from U-Boot");
}
