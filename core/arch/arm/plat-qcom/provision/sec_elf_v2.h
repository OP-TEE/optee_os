/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __SEC_ELF_V2_H__
#define __SEC_ELF_V2_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <utee_defines.h>

#define SECDAT_MAGIC1			0x3B7251CA
#define SECDAT_MAGIC2			0x2A126F29
#define SECDAT_VERSION_2		0x00000002

#define SECDAT_MAX_SUPPORTED_SEGMENT	32

#define SECDAT_SEGMENT_TYPE_EFUSE	0x00
#define SECDAT_SEGMENT_TYPE_ENCKEY	0x01

enum fuseprov_region_type {
	FUSEPROV_REGION_SECBOOT = 0,
	FUSEPROV_REGION_OEM_PK_HASH = 1,
	FUSEPROV_REGION_SHK = 2,
	FUSEPROV_REGION_OEM_CONFIG = 3,
	FUSEPROV_REGION_RW_PERM = 4,
	FUSEPROV_REGION_SPARE_REG19 = 5,
	FUSEPROV_REGION_GENERAL = 6,
	FUSEPROV_REGION_FEC_EN = 7,
	FUSEPROV_REGION_ANTI_ROLLBACK_2 = 8,
	FUSEPROV_REGION_ANTI_ROLLBACK_3 = 9,
	FUSEPROV_REGION_PK_HASH1 = 10,
	FUSEPROV_REGION_IMAGE_ENCR_KEY1 = 11,
	FUSEPROV_REGION_OEM_SECURE = 12,
	FUSEPROV_REGION_MRC_2_0 = 13,
	FUSEPROV_REGION_OEM_SPARE = 14,
	FUSEPROV_REGION_MAX
};

enum fuseprov_operation_type {
	FUSEPROV_OP_BLOW = 0x00,
	FUSEPROV_OP_VERIFYMASK0 = 0x01,
	FUSEPROV_OP_BLOW_RANDOM = 0x02,
};

struct secdat_hdr {
	uint32_t magic1;
	uint32_t magic2;
	uint32_t revision;
	uint32_t size;
	uint8_t info[16];
	uint32_t seg_num;
	uint32_t reserved[3];
} __packed;

struct segment_hdr {
	uint32_t offset;
	uint16_t type;
	uint16_t attribute;
} __packed;

struct fuse_entry {
	uint32_t region;
	uint32_t addr;
	uint32_t lsb_val;
	uint32_t msb_val;
	uint32_t operation;
} __packed;

struct qfuse_list_hdr {
	uint32_t revision;
	uint32_t size;
	uint32_t fuse_count;
	uint32_t reserved[4];
} __packed;

struct secdat_footer {
	uint8_t hash[TEE_SHA256_HASH_SIZE];
} __packed;

TEE_Result sec_elf_parse(const uint8_t *data, size_t size,
			 const struct secdat_hdr **hdr,
			 const struct segment_hdr **segments);

TEE_Result sec_elf_validate_hash(const uint8_t *data, size_t size,
				 const struct secdat_hdr *hdr);

TEE_Result sec_elf_find_segment(const uint8_t *data, size_t size,
				uint32_t seg_type,
				const uint8_t **seg_data,
				uint32_t *seg_size);

TEE_Result provision_oem_spare(const struct fuse_entry *entries,
			       uint32_t count, bool *fuses_blown);

TEE_Result provision_shk(const struct fuse_entry *entries, uint32_t count,
			 bool *fuses_blown);

TEE_Result provision_execute(const uint8_t *data, size_t len,
			     bool *fuses_blown);

void provision_reset_device(void);

#endif /* __SEC_ELF_V2_H__ */
