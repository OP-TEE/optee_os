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
 * Qualcomm MBN (Multiboot Binary) hash-segment parser.
 *
 * The INIT_IMAGE metadata blob produced by qcom_mdt_read_metadata() is:
 *   [ phdrs[0].p_filesz bytes ]  ELF header + program-header table
 *   [ hash-segment bytes      ]  verbatim content of the MBN hash-segment phdr
 *
 * The MBN hash segment (at phdrs[0].p_filesz) holds signing material:
 *
 *   v5 (40-byte header):
 *     [header][hash table][qti sig][qti certs][oem sig][oem certs]
 *   v6 (48-byte header):
 *     [header][qti meta][oem meta][hash table]
 *     [qti sig][qti certs][oem sig][oem certs]
 *
 * Hash table: one digest per ELF program header; entry 0 = digest of the ELF
 * header plus program-header table, entry i = digest of the segment at phdr i.
 *
 * This file extracts the hash table alone (CFG_QCOM_PAS_AUTH); the
 * OEM/QTI metadata, signature and certificate regions are pas_meta.h's
 * concern (CFG_QCOM_PAS_AUTH).
 */

#define PAS_MBN_VERSION_5	5
#define PAS_MBN_VERSION_6	6

/*
 * struct pas_mbn - parsed view of an MBN hash segment
 *
 * All pointers reference the caller-owned metadata buffer.
 *
 * @version:		MBN header version (PAS_MBN_VERSION_5 / _6)
 * @hash_table:		per-program-header digest table
 * @hash_table_size:	size of the hash table in bytes
 * @num_entries:	number of digests in the table
 * @hash_size:		digest size in bytes (32 = SHA-256, 48 = SHA-384)
 * @signed_region:	first byte covered by the signature
 * @signed_region_size:	number of bytes covered by the signature
 * @oem_meta:		OEM metadata block, NULL if absent (v6 only)
 * @oem_meta_size:	OEM metadata size in bytes
 * @oem_sig:		OEM signature (NULL if absent)
 * @oem_sig_size:	OEM signature size
 * @oem_certs:		OEM certificate chain, DER, leaf first (NULL if absent)
 * @oem_certs_size:	OEM certificate chain size
 * @qti_meta:		QTI metadata block, NULL if absent (v6 only)
 * @qti_meta_size:	QTI metadata size in bytes
 * @qti_sig:		QTI signature (NULL if not double-signed)
 * @qti_sig_size:	QTI signature size
 * @qti_certs:		QTI certificate chain (NULL if not double-signed)
 * @qti_certs_size:	QTI certificate chain size
 * @uie_encrypted:	true if the segment carries a UIE encryption parameter
 *			block (image content is encrypted)
 *
 * The oem_meta/oem_sig/oem_certs, qti_meta/qti_sig/qti_certs and
 * signed_region fields are populated by pas_mbn_parse() for pas_meta.c's
 * use under CFG_QCOM_PAS_AUTH; a CFG_QCOM_PAS_AUTH-only
 * build parses but never reads them.
 */
struct pas_mbn {
	uint32_t version;

	const uint8_t *hash_table;
	size_t hash_table_size;
	uint32_t num_entries;
	uint32_t hash_size;

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

/*
 * pas_mbn_parse() - parse the MBN hash segment inside an INIT_IMAGE blob
 * @md:		INIT_IMAGE metadata blob (ELF preamble + hash segment)
 * @md_size:	size of @md in bytes
 * @hash_size:	expected digest size (32 or 48); used to derive entry count
 * @out:	parsed result on success
 *
 * Return TEE_SUCCESS, TEE_ERROR_BAD_FORMAT, or TEE_ERROR_BAD_PARAMETERS.
 */
TEE_Result pas_mbn_parse(const uint8_t *md, size_t md_size,
			 uint32_t hash_size, struct pas_mbn *out);

#endif /* __PAS_MBN_PARSER_H */
