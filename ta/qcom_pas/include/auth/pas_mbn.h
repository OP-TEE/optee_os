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
 *   MBN hash segment, v6 (48-byte header):
 *     [header][qc meta][oem meta][hash table]
 *     [qc sig][qc certs][oem sig][oem certs]
 *
 * Hash table: one digest per ELF program header; entry 0 = digest of the ELF
 * header plus program-header table, entry i = digest of the segment at phdr i.
 */

#define PAS_MBN_VERSION_6	6

/*
 * struct pas_mbn - parsed view of an MBN hash segment
 *
 * All pointers reference the caller-owned metadata buffer.
 *
 * @version:		MBN header version (PAS_MBN_VERSION_*)
 * @hash_table:		per-program-header digest table
 * @hash_table_size:	size of the hash table in bytes
 * @num_entries:	number of digests in the table
 * @hash_size:		digest size in bytes (32 = SHA-256, 48 = SHA-384)
 * @signed_region:	first byte covered by the signature
 * @signed_region_size:	number of bytes covered by the signature
 * @oem_meta:		OEM metadata block, NULL if absent
 * @oem_meta_size:	OEM metadata size in bytes
 * @oem_sig:		OEM signature (NULL if absent)
 * @oem_sig_size:	OEM signature size
 * @oem_certs:		OEM certificate chain, DER, leaf first (NULL if absent)
 * @oem_certs_size:	OEM certificate chain size
 * @qc_meta:		QC metadata block, NULL if absent
 * @qc_meta_size:	QC metadata size in bytes
 * @qc_sig:		QC signature (NULL if not double-signed)
 * @qc_sig_size:	QC signature size
 * @qc_certs:		QC certificate chain (NULL if not double-signed)
 * @qc_certs_size:	QC certificate chain size
 * @uie_encrypted:	true if the segment carries a UIE encryption parameter
 *			block (image content is encrypted)
 *
 * The oem_*, qc_* and signed_region fields are populated by pas_mbn_parse()
 * for authentication.
 */
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
	const uint8_t *qc_meta;
	size_t qc_meta_size;
	const uint8_t *qc_sig;
	size_t qc_sig_size;
	const uint8_t *qc_certs;
	size_t qc_certs_size;
	bool uie_encrypted;
};

TEE_Result pas_mbn_parse(const uint8_t *metadata, size_t metadata_size,
			 uint32_t hash_len, struct pas_mbn *out);

TEE_Result pas_mbn_get_signed_data(const struct pas_mbn *mbn,
				   uint8_t **data, size_t *data_len);

#endif /* __AUTH_PAS_MBN_H */
