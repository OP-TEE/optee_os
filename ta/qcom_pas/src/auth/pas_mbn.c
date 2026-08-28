// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_mbn.h>
#include <elf32.h>
#include <elf64.h>
#include <string.h>
#include <tee_internal_api.h>
#include <util.h>

/* Header magic of the optional UIE encryption block in the hash segment. */
#define UIE_ENC_PARAM_MAGIC	0x514D5349	/* "ISMQ" */

/* Segment type lives in bits 24:26 of p_flags; 0x2 marks the hash segment. */
#define MBN_PT_FLAG_TYPE_MASK		0x07000000U
#define MBN_PT_FLAG_HASH_TYPE_MASK	0x02000000U

TEE_Result pas_mbn_get_hash_segment(const uint8_t *metadata,
				    size_t metadata_size,
				    const uint8_t **seg, size_t *seg_size)
{
	const unsigned char *ident = metadata;
	size_t phdr_entry_len = 0;
	size_t phdr_entry_min = 0;
	size_t phdr_table_end = 0;
	size_t phdr_offset = 0;
	size_t phdr_count = 0;
	uint32_t hash_flags = 0;
	size_t hash_seg_size = 0;
	size_t elf_hdr_len = 0;
	size_t hash_seg_offset = 0;
	size_t hash_seg_end = 0;
	bool is_64 = false;
	bool found = false;
	size_t i = 0;

	if (metadata_size < EI_NIDENT)
		return TEE_ERROR_BAD_FORMAT;

	if (ident[EI_MAG0] != ELFMAG0 || ident[EI_MAG1] != ELFMAG1 ||
	    ident[EI_MAG2] != ELFMAG2 || ident[EI_MAG3] != ELFMAG3)
		return TEE_ERROR_BAD_FORMAT;

	switch (ident[EI_CLASS]) {
	case ELFCLASS64:
		is_64 = true;
		elf_hdr_len = sizeof(Elf64_Ehdr);
		phdr_entry_min = sizeof(Elf64_Phdr);
		break;
	case ELFCLASS32:
		is_64 = false;
		elf_hdr_len = sizeof(Elf32_Ehdr);
		phdr_entry_min = sizeof(Elf32_Phdr);
		break;
	default:
		return TEE_ERROR_BAD_FORMAT;
	}

	if (metadata_size < elf_hdr_len)
		return TEE_ERROR_BAD_FORMAT;

	if (is_64) {
		const Elf64_Ehdr *ehdr = (const void *)metadata;

		phdr_offset = ehdr->e_phoff;
		phdr_entry_len = ehdr->e_phentsize;
		phdr_count = ehdr->e_phnum;
	} else {
		const Elf32_Ehdr *ehdr = (const void *)metadata;

		phdr_offset = ehdr->e_phoff;
		phdr_entry_len = ehdr->e_phentsize;
		phdr_count = ehdr->e_phnum;
	}

	if (phdr_count < 2 || phdr_offset != elf_hdr_len ||
	    phdr_entry_len != phdr_entry_min)
		return TEE_ERROR_BAD_FORMAT;

	if (MUL_OVERFLOW(phdr_entry_len, phdr_count, &phdr_table_end) ||
	    ADD_OVERFLOW(phdr_table_end, phdr_offset, &phdr_table_end) ||
	    phdr_table_end > metadata_size)
		return TEE_ERROR_BAD_FORMAT;

	for (i = 0; i < phdr_count; i++) {
		const uint8_t *p = metadata + phdr_offset + i * phdr_entry_len;

		if (is_64) {
			const Elf64_Phdr *phdr = (const void *)p;

			hash_flags = phdr->p_flags;
			hash_seg_size = phdr->p_filesz;
		} else {
			const Elf32_Phdr *phdr = (const void *)p;

			hash_flags = phdr->p_flags;
			hash_seg_size = phdr->p_filesz;
		}

		if ((hash_flags & MBN_PT_FLAG_TYPE_MASK) ==
		    MBN_PT_FLAG_HASH_TYPE_MASK) {
			found = true;
			break;
		}
	}
	if (!found)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * The hash segment is packed immediately after the ELF header and
	 * program-header table, so its offset is the ELF header length plus
	 * the phdr table length. The phdr p_offset refers to the original
	 * firmware file and must not be used here.
	 */
	if (MUL_OVERFLOW(phdr_entry_len, phdr_count, &hash_seg_offset) ||
	    ADD_OVERFLOW(hash_seg_offset, elf_hdr_len, &hash_seg_offset))
		return TEE_ERROR_BAD_FORMAT;

	if (ADD_OVERFLOW(hash_seg_offset, hash_seg_size, &hash_seg_end) ||
	    hash_seg_end > metadata_size || !hash_seg_size)
		return TEE_ERROR_BAD_FORMAT;

	*seg = metadata + hash_seg_offset;
	*seg_size = hash_seg_size;

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_get_region(const uint8_t *segment, size_t segment_size,
			      size_t *offset, size_t len,
			      const uint8_t **region, size_t *region_len)
{
	if (!len) {
		*region = NULL;
		*region_len = 0;
		return TEE_SUCCESS;
	}

	if (len > segment_size || *offset > segment_size - len)
		return TEE_ERROR_BAD_FORMAT;

	*region = segment + *offset;
	*region_len = len;
	*offset += len;

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_parse(const uint8_t *metadata, size_t metadata_size,
			 uint32_t hash_len, struct pas_hash_segment_info *out)
{
	struct pas_mbn_header_v6 header = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *hash_seg = NULL;
	uint32_t oem_cert_size = 0;
	uint32_t oem_meta_size = 0;
	uint32_t oem_sig_size = 0;
	uint32_t qc_cert_size = 0;
	uint32_t qc_meta_size = 0;
	size_t hash_seg_size = 0;
	uint32_t qc_sig_size = 0;
	size_t signed_size = 0;
	uint32_t code_size = 0;
	uint32_t version = 0;
	size_t hdr_size = 0;
	size_t offset = 0;

	if (!metadata || !metadata_size || !out || !hash_len)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(out, 0, sizeof(*out));

	res = pas_mbn_get_hash_segment(metadata, metadata_size, &hash_seg,
				       &hash_seg_size);
	if (res)
		return res;

	if (hash_seg_size < sizeof(header))
		return TEE_ERROR_BAD_FORMAT;

	memcpy(&header, hash_seg, sizeof(header));
	version = header.version;
	if (version != PAS_MBN_VERSION_6) {
		EMSG("PAS auth: unsupported MBN version %#"PRIx32, version);
		return TEE_ERROR_BAD_FORMAT;
	}
	hdr_size = sizeof(header);

	/* "code_size" is the hash-table length in bytes, not a code length. */
	code_size = header.code_size;
	qc_sig_size = header.qc_signature_size;
	qc_cert_size = header.qc_cert_chain_size;
	oem_sig_size = header.oem_signature_size;
	oem_cert_size = header.oem_cert_chain_size;
	qc_meta_size = header.qc_metadata_size;
	oem_meta_size = header.oem_metadata_size;

	if (!code_size || code_size % hash_len)
		return TEE_ERROR_BAD_FORMAT;

	/*
	 * Payload after the header:
	 *   [qc_meta][oem_meta][hash table][qc_sig][qc_cert][oem_sig][oem_cert]
	 * The signed region spans the header plus
	 * [qc_meta || oem_meta || hash table].
	 */
	offset = hdr_size;
	out->signed_region = hash_seg;

	if (ADD_OVERFLOW(qc_meta_size, oem_meta_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, code_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, hdr_size, &signed_size))
		return TEE_ERROR_BAD_FORMAT;

	if (signed_size > hash_seg_size)
		return TEE_ERROR_BAD_FORMAT;
	out->signed_region_size = signed_size;

	res = pas_mbn_get_region(hash_seg, hash_seg_size, &offset, qc_meta_size,
				 &out->qc_meta, &out->qc_meta_size);
	if (res)
		return res;
	res = pas_mbn_get_region(hash_seg, hash_seg_size, &offset,
				 oem_meta_size, &out->oem_meta,
				 &out->oem_meta_size);
	if (res)
		return res;

	out->hash_table = hash_seg + offset;
	out->hash_table_size = code_size;
	out->hash_len = hash_len;
	out->num_entries = code_size / hash_len;
	offset += code_size;

	res = pas_mbn_get_region(hash_seg, hash_seg_size, &offset, qc_sig_size,
				 &out->qc_sig, &out->qc_sig_size);
	if (res)
		return res;
	res = pas_mbn_get_region(hash_seg, hash_seg_size, &offset, qc_cert_size,
				 &out->qc_certs, &out->qc_certs_size);
	if (res)
		return res;
	res = pas_mbn_get_region(hash_seg, hash_seg_size, &offset, oem_sig_size,
				 &out->oem_sig, &out->oem_sig_size);
	if (res)
		return res;
	res = pas_mbn_get_region(hash_seg, hash_seg_size, &offset,
				 oem_cert_size, &out->oem_certs,
				 &out->oem_certs_size);
	if (res)
		return res;

	out->version = version;

	if (offset + sizeof(uint32_t) <= hash_seg_size) {
		uint32_t uie_magic = 0;

		memcpy(&uie_magic, hash_seg + offset, sizeof(uie_magic));
		if (uie_magic == UIE_ENC_PARAM_MAGIC)
			out->uie_encrypted = true;
	}

	return TEE_SUCCESS;
}
