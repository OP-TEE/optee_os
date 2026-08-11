/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __AUTH_PAS_MBN_H
#define __AUTH_PAS_MBN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * On-wire layout of the INIT_IMAGE metadata blob:
 *   [ phdrs[0].p_filesz bytes ]  ELF header + program-header table
 *   [ hash-segment bytes      ]  verbatim MBN hash-segment phdr content
 *
 * MBN hash segment, v6 (48-byte header):
 *   [header][qti meta][oem meta][hash table]
 *   [qti sig][qti certs][oem sig][oem certs]
 *
 * Hash table: one digest per ELF program header; entry 0 = digest of the ELF
 * header plus program-header table, entry i = digest of the segment at phdr i.
 */

#define PAS_MBN_VERSION_6	6

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

struct pas_mbn {
	uint32_t version;

	const uint8_t *hash_table;
	size_t hash_table_size;
	uint32_t num_entries;
	uint32_t hash_len;

	const uint8_t *signed_region;
	size_t signed_region_size;

	const uint8_t *oem_meta;
	size_t oem_meta_size;
	const uint8_t *oem_sig;
	size_t oem_sig_size;
	const uint8_t *oem_certs;
	size_t oem_certs_size;

	const uint8_t *qti_meta;
	size_t qti_meta_size;
	const uint8_t *qti_sig;
	size_t qti_sig_size;
	const uint8_t *qti_certs;
	size_t qti_certs_size;

	bool uie_encrypted;
};

/* Read a little-endian uint32_t from @p. */
uint32_t pas_mbn_read_u32(const uint8_t *p);

TEE_Result pas_mbn_locate(const uint8_t *md, size_t md_size,
			  const uint8_t **seg, size_t *seg_size);

TEE_Result pas_mbn_reserve_region(const uint8_t *segment, size_t segment_size,
				  size_t *offset, size_t len,
				  const uint8_t **region, size_t *region_len);

TEE_Result pas_mbn_parse(const uint8_t *md, size_t md_size,
			 uint32_t hash_len, struct pas_mbn *out);

#endif /* __AUTH_PAS_MBN_H */
