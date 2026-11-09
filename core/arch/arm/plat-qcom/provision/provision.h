/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PROVISION_H__
#define __PROVISION_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#include "provision_backend.h"

/* Value of fuse_entry::operation that programs the given values */
#define PROVISION_OP_BLOW	0x00

/*
 * One fuse list entry. The layout is shared by all data formats, the numeric
 * values of @region and @operation (other than PROVISION_OP_BLOW) are defined
 * by the format and are interpreted through struct provision_policy.
 */
struct fuse_entry {
	uint32_t region;
	uint32_t addr;
	uint32_t lsb_val;
	uint32_t msb_val;
	uint32_t operation;
} __packed;

/* Programming groups, a format maps its region values onto these */
enum provision_category {
	PROV_CAT_NONE = 0,	/* Not a valid region: never programmed */
	PROV_CAT_GENERAL,
	PROV_CAT_SECBOOT,
	PROV_CAT_SHK,
	PROV_CAT_OEM_CONFIG,
	PROV_CAT_FEC_EN,
	PROV_CAT_RW_PERM,
};

struct provision_policy;

/* One programming step. @category is passed to @fn unchanged. */
struct provision_pass {
	TEE_Result (*fn)(const struct provision_backend *be,
			 const struct provision_policy *pol,
			 enum provision_category category,
			 const struct fuse_entry *entries, uint32_t count,
			 bool *fuses_blown);
	enum provision_category category;
};

/* What differs between data formats */
struct provision_policy {
	/* Group of the entries of @region */
	enum provision_category (*category)(uint32_t region);
	/* Whether the row of @entry has FEC bits */
	TEE_Result (*row_has_fec)(const struct provision_backend *be,
				  const struct fuse_entry *entry,
				  bool *has_fec);
	/* Whether the row, currently holding @cur, already has @entry's bits */
	bool (*row_programmed)(const uint32_t cur[2],
			       const struct fuse_entry *entry, bool has_fec);
	/* Value to program for @entry */
	void (*row_value)(const struct fuse_entry *entry, bool has_fec,
			  uint32_t data[2]);
	/* Steps in the order they are run */
	const struct provision_pass *passes;
	size_t num_passes;
};

/* Program the BLOW entries of @category, one row at a time */
TEE_Result provision_blow_category(const struct provision_backend *be,
				   const struct provision_policy *pol,
				   enum provision_category category,
				   const struct fuse_entry *entries,
				   uint32_t count, bool *fuses_blown);

/*
 * Run the passes of @pol over @entries between be->begin() and be->end().
 * @fuses_blown reports confirmed row writes, including on error. A false
 * value does not exclude partial programming by a failed row operation.
 */
TEE_Result provision_run(const struct provision_backend *be,
			 const struct provision_policy *pol,
			 const struct fuse_entry *entries, uint32_t count,
			 bool *fuses_blown);

void provision_reset_device(void);

#endif /* __PROVISION_H__ */
