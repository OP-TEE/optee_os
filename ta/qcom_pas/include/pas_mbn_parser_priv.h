/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_MBN_PARSER_PRIV_H
#define __PAS_MBN_PARSER_PRIV_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * MBN hash-segment binary-format primitives, shared between pas_mbn_parser.c
 * (locates the segment and extracts the hash table) and pas_meta.c
 * (extracts the OEM/QTI metadata, signature and certificate regions from
 * the same segment). Both are built under CFG_QCOM_PAS_AUTH and
 * implemented in pas_mbn_parser.c.
 */

/* MBN header field offsets (bytes from hash-segment start) */
#define MBN_OFF_VERSION		0x04
#define MBN_OFF_QC_SIG_SIZE	0x08
#define MBN_OFF_QC_CERT_SIZE	0x0c
#define MBN_OFF_CODE_SIZE	0x14
#define MBN_OFF_OEM_SIG_SIZE	0x1c
#define MBN_OFF_OEM_CERT_SIZE	0x24
#define MBN_OFF_QC_META_SIZE	0x28	/* v6 only */
#define MBN_OFF_OEM_META_SIZE	0x2c	/* v6 only */

#define MBN_HDR_SIZE_V5		0x28
#define MBN_HDR_SIZE_V6		0x30

/* Read a little-endian uint32_t from @p. */
uint32_t pas_mbn_read_u32(const uint8_t *p);

/*
 * pas_mbn_locate() - locate the MBN hash segment inside an INIT_IMAGE blob
 * @md:       INIT_IMAGE metadata blob (ELF preamble + hash segment)
 * @md_size:  size of @md in bytes
 * @seg:      out: pointer to the hash segment
 * @seg_size: out: size of the hash segment in bytes
 * @preamble: out (optional): byte count of the ELF header + program-header
 *            table preamble that precedes the hash segment; pass NULL when
 *            not needed
 *
 * The blob starts with phdrs[0].p_filesz bytes of ELF header plus
 * program-header table; the hash segment follows immediately.
 */
TEE_Result pas_mbn_locate(const uint8_t *md, size_t md_size,
			  const uint8_t **seg, size_t *seg_size,
			  size_t *preamble);

/*
 * pas_mbn_take_region() - slice a sub-region out of the hash segment
 * @seg:      hash segment from pas_mbn_locate()
 * @seg_size: size of @seg in bytes
 * @cursor:   in/out: byte offset within @seg; advanced by @len on success
 * @len:      length of the region to slice; 0 yields a NULL/zero-length
 *            region without moving @cursor
 * @ptr:      out: pointer to the region, or NULL when @len is 0
 * @ptr_len:  out: length of the region
 */
TEE_Result pas_mbn_take_region(const uint8_t *seg, size_t seg_size,
			       size_t *cursor, size_t len,
			       const uint8_t **ptr, size_t *ptr_len);

#endif /* __PAS_MBN_PARSER_PRIV_H */
