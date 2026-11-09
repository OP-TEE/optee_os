/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __SEC_ELF_V3_H__
#define __SEC_ELF_V3_H__

#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#include "provision.h"

/*
 * Flat fuse data format, revision 3: a header followed by num_entries
 * struct fuse_entry records. There are no segments, no footer and no hash:
 * the authenticity of the data must be established before it reaches this
 * parser.
 */
#define SECDAT_V3_MAGIC1		0x3B7251CA
#define SECDAT_V3_MAGIC2		0x2A126F29
#define SECDAT_V3_REVISION		U(3)

/* More random rows than this in one region cannot be programmed */
#define SECDAT_V3_MAX_RANDOM_ROWS	U(5)

struct secdat_v3_hdr {
	uint32_t magic1;
	uint32_t magic2;
	uint32_t revision;
	uint32_t num_entries;
} __packed;

/* Values of fuse_entry::region. Any other value is programmed as GENERAL. */
enum secdat_v3_region {
	SECDAT_V3_REGION_OEM_SEC_BOOT = 0x0,
	SECDAT_V3_REGION_OEM_PK_HASH = 0x1,
	SECDAT_V3_REGION_SEC_HW_KEY = 0x2,
	SECDAT_V3_REGION_OEM_CONFIG = 0x3,
	SECDAT_V3_REGION_READ_PERM = 0x4,
	SECDAT_V3_REGION_WRITE_PERM = 0x5,
	SECDAT_V3_REGION_FEC_EN = 0x6,
	SECDAT_V3_REGION_ANTI_ROLLBACK = 0x7,
	SECDAT_V3_REGION_IMAGE_ENCR_KEY = 0x8,
	SECDAT_V3_REGION_MRC_2_0 = 0x9,
	SECDAT_V3_REGION_OEM_SPARE = 0xA,
	SECDAT_V3_REGION_OEM_PRODUCT_SEED = 0xB,
};

/* Values of fuse_entry::operation. Any other value is ignored. */
enum secdat_v3_operation {
	SECDAT_V3_OP_BLOW = 0x0,
	SECDAT_V3_OP_BLOW_RANDOM = 0x1,
};

/*
 * Check the image in @data and return its fuse list in @entries/@count. The
 * entries point into @data.
 *
 * Return TEE_ERROR_ITEM_NOT_FOUND if @data does not start with the image
 * magic, which is how an empty buffer looks: there is nothing to program.
 * Return TEE_ERROR_BAD_FORMAT if there is an image but it is not valid. No
 * fuse is touched by this function.
 */
TEE_Result sec_elf_v3_parse(const uint8_t *data, size_t len,
			    const struct fuse_entry **entries,
			    uint32_t *count);

#endif /* __SEC_ELF_V3_H__ */
