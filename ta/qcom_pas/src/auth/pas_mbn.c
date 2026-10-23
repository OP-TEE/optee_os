// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_mbn.h>
#include <elf32.h>
#include <elf64.h>
#include "pas_mbn_parser_common.h"
#include <string.h>
#include <tee_internal_api.h>
#include <util.h>

/* Header magic of the optional UIE encryption block in the hash segment. */
#define UIE_ENC_PARAM_MAGIC	0x514D5349	/* "ISMQ" */

/* Segment type lives in bits 24:26 of p_flags; 0x2 marks the hash segment. */
#define MBN_PT_FLAG_TYPE_MASK		0x07000000U
#define MBN_PT_FLAG_HASH_TYPE_MASK	0x02000000U

uint32_t pas_mbn_read_u32(const uint8_t *p)
{
	uint32_t v = 0;

	memcpy(&v, p, sizeof(v));

	return v;
}

uint64_t pas_mbn_read_u64(const uint8_t *p)
{
	uint64_t v = 0;

	memcpy(&v, p, sizeof(v));

	return v;
}

TEE_Result pas_mbn_get_version(const uint8_t *segment, size_t segment_size,
			       uint32_t *version)
{
	if (!segment || !version)
		return TEE_ERROR_BAD_PARAMETERS;

	if (segment_size < 2 * sizeof(uint32_t))
		return TEE_ERROR_BAD_FORMAT;

	*version = pas_mbn_read_u32(segment + sizeof(uint32_t));

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_locate(const uint8_t *metadata, size_t metadata_size,
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

TEE_Result pas_mbn_reserve_region(const uint8_t *segment, size_t segment_size,
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

static const struct pas_mbn_ops *pas_mbn_get_ops(uint32_t version)
{
	switch (version) {
	case PAS_MBN_VERSION_6:
		return &pas_mbn_v6_ops;
	case PAS_MBN_VERSION_7:
		return &pas_mbn_v7_ops;
	default:
		return NULL;
	}
}

TEE_Result pas_mbn_parse_layout(const uint8_t *segment, size_t segment_size,
				uint32_t hash_len,
				const struct pas_mbn_layout *layout,
				struct pas_mbn *mbn)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t signed_size = 0;
	size_t offset = 0;

	if (!segment || !hash_len || !layout || !mbn)
		return TEE_ERROR_BAD_PARAMETERS;

	if (layout->header_size > segment_size || !layout->hash_table_size ||
	    layout->hash_table_size % hash_len)
		return TEE_ERROR_BAD_FORMAT;

	if (ADD_OVERFLOW(layout->common_meta_size, layout->qc_meta_size,
			 &signed_size) ||
	    ADD_OVERFLOW(signed_size, layout->oem_meta_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, layout->hash_table_size, &signed_size) ||
	    ADD_OVERFLOW(signed_size, layout->header_size, &signed_size) ||
	    signed_size > segment_size)
		return TEE_ERROR_BAD_FORMAT;

	mbn->version = layout->version;
	mbn->signed_region = segment;
	mbn->signed_region_size = signed_size;
	offset = layout->header_size;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     layout->common_meta_size,
				     &mbn->common_meta,
				     &mbn->common_meta_size);
	if (res)
		return res;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     layout->qc_meta_size, &mbn->qc_meta,
				     &mbn->qc_meta_size);
	if (res)
		return res;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     layout->oem_meta_size, &mbn->oem_meta,
				     &mbn->oem_meta_size);
	if (res)
		return res;

	mbn->hash_table = segment + offset;
	mbn->hash_table_size = layout->hash_table_size;
	mbn->hash_len = hash_len;
	mbn->num_entries = layout->hash_table_size / hash_len;
	offset += layout->hash_table_size;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     layout->qc_sig_size, &mbn->qc_sig,
				     &mbn->qc_sig_size);
	if (res)
		return res;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     layout->qc_certs_size, &mbn->qc_certs,
				     &mbn->qc_certs_size);
	if (res)
		return res;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     layout->oem_sig_size, &mbn->oem_sig,
				     &mbn->oem_sig_size);
	if (res)
		return res;

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     layout->oem_certs_size, &mbn->oem_certs,
				     &mbn->oem_certs_size);
	if (res)
		return res;

	if (offset <= segment_size &&
	    sizeof(uint32_t) <= segment_size - offset &&
	    pas_mbn_read_u32(segment + offset) == UIE_ENC_PARAM_MAGIC)
		mbn->uie_encrypted = true;

	return TEE_SUCCESS;
}

static void mask_region(uint8_t *copy, size_t copy_len,
			const uint8_t *region, size_t region_len,
			const uint8_t *base)
{
	size_t offset = 0;

	if (!region || !region_len)
		return;

	offset = region - base;
	if (offset < copy_len && region_len <= copy_len - offset)
		memset(copy + offset, 0, region_len);
}

static void zero_u32(uint8_t *copy, size_t copy_len, size_t offset)
{
	if (offset <= copy_len && sizeof(uint32_t) <= copy_len - offset)
		memset(copy + offset, 0, sizeof(uint32_t));
}

TEE_Result pas_mbn_copy_signed_data(const struct pas_mbn *mbn,
				    size_t qc_sig_size_offset,
				    size_t qc_certs_size_offset,
				    uint8_t **data, size_t *data_len)
{
	uint8_t *copy = NULL;

	if (!mbn || !mbn->signed_region || !mbn->signed_region_size || !data ||
	    !data_len)
		return TEE_ERROR_BAD_PARAMETERS;

	copy = TEE_Malloc(mbn->signed_region_size, TEE_MALLOC_FILL_ZERO);
	if (!copy) {
		EMSG("OOM origin: signed-data allocation failed (size=%zu)",
		     mbn->signed_region_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memcpy(copy, mbn->signed_region, mbn->signed_region_size);
	zero_u32(copy, mbn->signed_region_size, qc_sig_size_offset);
	zero_u32(copy, mbn->signed_region_size, qc_certs_size_offset);
	mask_region(copy, mbn->signed_region_size, mbn->qc_meta,
			    mbn->qc_meta_size, mbn->signed_region);

	*data = copy;
	*data_len = mbn->signed_region_size;

	return TEE_SUCCESS;
}

TEE_Result pas_mbn_parse(const uint8_t *metadata, size_t metadata_size,
			 uint32_t hash_len, struct pas_mbn *mbn)
{
	const struct pas_mbn_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *segment = NULL;
	uint32_t version = 0;
	size_t segment_size = 0;

	if (!metadata || !metadata_size || !mbn || !hash_len)
		return TEE_ERROR_BAD_PARAMETERS;

	memset(mbn, 0, sizeof(*mbn));

	res = pas_mbn_locate(metadata, metadata_size, &segment, &segment_size);
	if (res)
		return res;

	res = pas_mbn_get_version(segment, segment_size, &version);
	if (res)
		return res;

	ops = pas_mbn_get_ops(version);
	if (!ops) {
		EMSG("PAS auth: unsupported MBN version %"PRIu32, version);
		return TEE_ERROR_BAD_FORMAT;
	}

	return ops->parse(segment, segment_size, hash_len, mbn);
}

TEE_Result pas_mbn_get_signed_data(const struct pas_mbn *mbn,
				   uint8_t **data, size_t *data_len)
{
	const struct pas_mbn_ops *ops = NULL;

	if (!mbn || !data || !data_len)
		return TEE_ERROR_BAD_PARAMETERS;

	ops = pas_mbn_get_ops(mbn->version);
	if (!ops)
		return TEE_ERROR_BAD_FORMAT;

	return ops->get_signed_data(mbn, data, data_len);
}
