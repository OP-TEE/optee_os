/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_MBN_PARSER_H
#define __PAS_MBN_PARSER_H

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

TEE_Result pas_mbn_parse(const uint8_t *md, size_t md_size,
			 uint32_t hash_len, struct pas_mbn *out);

#endif /* __PAS_MBN_PARSER_H */
