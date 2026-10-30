/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __SEC_ELF_V3_H__
#define __SEC_ELF_V3_H__

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

/* Fuse region an entry belongs to, as numbered in the image */
enum fuseprov_v3_region_type {
	FUSEPROV_V3_REGION_TYPE_OEM_SEC_BOOT = 0,
	FUSEPROV_V3_REGION_TYPE_OEM_PK_HASH = 1,
	FUSEPROV_V3_REGION_TYPE_SEC_HW_KEY = 2,
	FUSEPROV_V3_REGION_TYPE_OEM_CONFIG = 3,
	FUSEPROV_V3_REGION_TYPE_READ_PERM = 4,
	FUSEPROV_V3_REGION_TYPE_WRITE_PERM = 5,
	FUSEPROV_V3_REGION_TYPE_FEC_EN = 6,
	FUSEPROV_V3_REGION_TYPE_ANTI_ROLLBACK = 7,
	FUSEPROV_V3_REGION_TYPE_IMAGE_ENCR_KEY = 8,
	FUSEPROV_V3_REGION_TYPE_MRC_2_0 = 9,
	FUSEPROV_V3_REGION_TYPE_OEM_SPARE = 10,
	FUSEPROV_V3_REGION_TYPE_OEM_PRODUCT_SEED = 11,
	FUSEPROV_V3_REGION_TYPE_TME_RW_PERM = 12,
	FUSEPROV_V3_REGION_TYPE_TME_FEC_EN = 13,
	FUSEPROV_V3_REGION_TYPE_TME_OEM = 14,
	FUSEPROV_V3_REGION_TYPE_TME_SPARE = 15,
	FUSEPROV_V3_REGION_TYPE_MAX
};

/* Bobcat fuse list: a header and a flat array of entries, no segments */
struct secdat_v3_hdr {
	uint32_t magic1;
	uint32_t magic2;
	uint32_t revision;
	uint32_t num_entries;
} __packed;

struct secdat_v3_entry {
	uint32_t region_type;
	uint32_t fuse_addr;
	uint32_t lsb_val;
	uint32_t msb_val;
	uint32_t operation_type;
} __packed;

/* Validate the fuse list in @data; the returned @entries point into it */
TEE_Result sec_elf_v3_parse(const void *data, size_t len,
			    const struct secdat_v3_entry **entries,
			    uint32_t *num_entries);

#endif /* __SEC_ELF_V3_H__ */
