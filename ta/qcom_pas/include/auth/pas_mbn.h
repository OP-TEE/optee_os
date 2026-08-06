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
 *   v6 (48-byte header):
 *     [header][qti meta][oem meta][hash table]
 *     [qti sig][qti certs][oem sig][oem certs]
 *   v7 (40-byte header):
 *     [header][common meta][qti meta][oem meta][hash table]
 *     [qti sig][qti certs][oem sig][oem certs]
 *
 * v7 adds a common-metadata block shared by both signers (holding the hash
 * table's digest algorithm, among other fields) ahead of the per-signer
 * metadata; its header uses a different field layout and offsets from v6
 * (see pas_mbn_parser_priv.h) but the same "fixed header, then concatenated
 * variable-length regions" shape.
 *
 * Hash table: one digest per ELF program header; entry 0 = digest of the ELF
 * header plus program-header table, entry i = digest of the segment at phdr i.
 */

#define PAS_MBN_VERSION_6	6
#define PAS_MBN_VERSION_7	7

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

/*
 * struct pas_mbn - parsed view of an MBN hash segment
 *
 * All pointers reference the caller-owned metadata buffer.
 *
 * @version:		MBN header version (PAS_MBN_VERSION_6 / _7)
 * @hash_table:		per-program-header digest table
 * @hash_table_size:	size of the hash table in bytes
 * @num_entries:	number of digests in the table
 * @hash_size:		digest size in bytes (32 = SHA-256, 48 = SHA-384)
 * @signed_region:	first byte covered by the signature
 * @signed_region_size:	number of bytes covered by the signature
 * @common_meta:	v7 common metadata block, NULL if absent (v7 only)
 * @common_meta_size:	common metadata size in bytes
 * @oem_meta:		OEM metadata block, NULL if absent (v6/v7 only)
 * @oem_meta_size:	OEM metadata size in bytes
 * @oem_sig:		OEM signature (NULL if absent)
 * @oem_sig_size:	OEM signature size
 * @oem_certs:		OEM certificate chain, DER, leaf first (NULL if absent)
 * @oem_certs_size:	OEM certificate chain size
 * @qti_meta:		QTI metadata block, NULL if absent (v6/v7 only)
 * @qti_meta_size:	QTI metadata size in bytes
 * @qti_sig:		QTI signature (NULL if not double-signed)
 * @qti_sig_size:	QTI signature size
 * @qti_certs:		QTI certificate chain (NULL if not double-signed)
 * @qti_certs_size:	QTI certificate chain size
 * @uie_encrypted:	true if the segment carries a UIE encryption parameter
 *			block (image content is encrypted)
 *
 * The common_meta/oem_meta/oem_sig/oem_certs, qti_meta/qti_sig/qti_certs and
 * signed_region fields are populated by pas_mbn_parse() for pas_meta.c's
 * use under CFG_QCOM_PAS_AUTH; a CFG_QCOM_PAS_AUTH-only
 * build parses but never reads them.
 */
struct pas_mbn {
	uint32_t version;

	const uint8_t *hash_table;
	size_t hash_table_size;
	uint32_t num_entries;
	uint32_t hash_len;

	const uint8_t *signed_region;
	size_t signed_region_size;

	const uint8_t *common_meta;
	size_t common_meta_size;

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

TEE_Result pas_mbn_get_hash_segment(const uint8_t *md, size_t md_size,
				    const uint8_t **seg, size_t *seg_size);

TEE_Result pas_mbn_get_region(const uint8_t *segment, size_t segment_size,
			      size_t *offset, size_t len,
			      const uint8_t **region, size_t *region_len);

TEE_Result pas_mbn_parse(const uint8_t *md, size_t md_size,
			 uint32_t hash_len, struct pas_mbn *out);

#endif /* __AUTH_PAS_MBN_H */
