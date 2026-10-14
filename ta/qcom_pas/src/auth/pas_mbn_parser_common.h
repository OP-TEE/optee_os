/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_MBN_PARSER_COMMON_H
#define __PAS_MBN_PARSER_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <auth/pas_mbn.h>
#include <tee_api_types.h>

/* MBN header field offsets (bytes from hash-segment start) */
#define MBN_OFF_VERSION		0x04
#define MBN_OFF_QC_SIG_SIZE	0x08
#define MBN_OFF_QC_CERT_SIZE	0x0c
#define MBN_OFF_CODE_SIZE	0x14
#define MBN_OFF_OEM_SIG_SIZE	0x1c
#define MBN_OFF_OEM_CERT_SIZE	0x24
#define MBN_OFF_QC_META_SIZE	0x28
#define MBN_OFF_OEM_META_SIZE	0x2c

#define MBN_HDR_SIZE_V6		0x30

#define MBN_OFF_V7_VERSION		0x04
#define MBN_OFF_V7_COMMON_META_SIZE	0x08
#define MBN_OFF_V7_QC_META_SIZE		0x0c
#define MBN_OFF_V7_OEM_META_SIZE	0x10
#define MBN_OFF_V7_CODE_SIZE		0x14
#define MBN_OFF_V7_QC_SIG_SIZE		0x18
#define MBN_OFF_V7_QC_CERT_SIZE		0x1c
#define MBN_OFF_V7_OEM_SIG_SIZE		0x20
#define MBN_OFF_V7_OEM_CERT_SIZE	0x24

#define MBN_HDR_SIZE_V7			0x28

struct pas_mbn_layout {
	uint32_t version;
	size_t header_size;
	size_t common_meta_size;
	size_t qti_meta_size;
	size_t oem_meta_size;
	size_t hash_table_size;
	size_t qti_sig_size;
	size_t qti_certs_size;
	size_t oem_sig_size;
	size_t oem_certs_size;
};

struct pas_mbn_ops {
	uint32_t version;
	TEE_Result (*parse)(const uint8_t *segment, size_t segment_size,
			    uint32_t hash_len, struct pas_mbn *mbn);
	TEE_Result (*get_signed_data)(const struct pas_mbn *mbn,
				      uint8_t **data, size_t *data_len);
};

extern const struct pas_mbn_ops pas_mbn_v6_ops;
extern const struct pas_mbn_ops pas_mbn_v7_ops;

/* Read a little-endian uint32_t from @p. */
uint32_t pas_mbn_read_u32(const uint8_t *p);

/* Read a little-endian uint64_t from @p. */
uint64_t pas_mbn_read_u64(const uint8_t *p);

TEE_Result pas_mbn_locate(const uint8_t *md, size_t md_size,
			  const uint8_t **seg, size_t *seg_size);

TEE_Result pas_mbn_get_version(const uint8_t *segment, size_t segment_size,
			       uint32_t *version);

TEE_Result pas_mbn_reserve_region(const uint8_t *segment, size_t segment_size,
				  size_t *offset, size_t len,
				  const uint8_t **region, size_t *region_len);

TEE_Result pas_mbn_parse_layout(const uint8_t *segment, size_t segment_size,
				uint32_t hash_len,
				const struct pas_mbn_layout *layout,
				struct pas_mbn *mbn);

TEE_Result pas_mbn_copy_signed_data(const struct pas_mbn *mbn,
				    size_t qti_sig_size_offset,
				    size_t qti_certs_size_offset,
				    uint8_t **data, size_t *data_len);

#endif /* __PAS_MBN_PARSER_COMMON_H */
