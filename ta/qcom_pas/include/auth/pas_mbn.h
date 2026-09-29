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
 *   [header][qc meta][oem meta][hash table]
 *   [qc sig][qc certs][oem sig][oem certs]
 *
 * Hash table: one digest per ELF program header; entry 0 = digest of the ELF
 * header plus program-header table, entry i = digest of the segment at phdr i.
 */

#define PAS_MBN_VERSION_6	6

struct pas_mbn_header_v6 {
	uint32_t reserved0;
	uint32_t version;
	uint32_t qc_signature_size;
	uint32_t qc_cert_chain_size;
	uint32_t image_size;
	uint32_t code_size;
	uint32_t reserved1;
	uint32_t oem_signature_size;
	uint32_t reserved2;
	uint32_t oem_cert_chain_size;
	uint32_t qc_metadata_size;
	uint32_t oem_metadata_size;
};

struct pas_hash_segment_info {
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
	const uint8_t *qc_meta;
	size_t qc_meta_size;
	const uint8_t *qc_sig;
	size_t qc_sig_size;
	const uint8_t *qc_certs;
	size_t qc_certs_size;
	bool uie_encrypted;
};

TEE_Result pas_mbn_get_hash_segment(const uint8_t *md, size_t md_size,
				    const uint8_t **seg, size_t *seg_size);

TEE_Result pas_mbn_get_region(const uint8_t *segment, size_t segment_size,
			      size_t *offset, size_t len,
			      const uint8_t **region, size_t *region_len);

TEE_Result pas_mbn_parse(const uint8_t *md, size_t md_size,
			 uint32_t hash_len, struct pas_hash_segment_info *out);

#endif /* __AUTH_PAS_MBN_H */
