/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_MBN_PARSER_PRIV_H
#define __PAS_MBN_PARSER_PRIV_H

#include <stddef.h>
#include <stdint.h>
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

/* Read a little-endian uint32_t from @p. */
uint32_t pas_mbn_read_u32(const uint8_t *p);

TEE_Result pas_mbn_locate(const uint8_t *md, size_t md_size,
			  const uint8_t **seg, size_t *seg_size);

TEE_Result pas_mbn_reserve_region(const uint8_t *segment, size_t segment_size,
				  size_t *offset, size_t len,
				  const uint8_t **region, size_t *region_len);

#endif /* __PAS_MBN_PARSER_PRIV_H */
