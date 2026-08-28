// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_mbn.h>
#include <auth/pas_meta.h>
#include <elf32.h>
#include <elf64.h>
#include <stddef.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <utee_defines.h>
#include <util.h>

TEE_Result pas_meta_get_root_cert_sel(const uint8_t *meta_data,
				      size_t meta_data_size,
				      uint32_t *root_cert_sel)
{
	struct pas_mbn_header_v6 header = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *oem_meta = NULL;
	const uint8_t *qc_meta = NULL;
	const uint8_t *segment = NULL;
	size_t oem_metadata_size = 0;
	size_t qc_metadata_size = 0;
	size_t segment_size = 0;
	uint32_t version = 0;
	size_t hdr_size = 0;
	size_t offset = 0;

	if (!meta_data || !meta_data_size || !root_cert_sel)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_mbn_get_hash_segment(meta_data, meta_data_size, &segment,
				       &segment_size);
	if (res)
		return res;

	if (segment_size < sizeof(header))
		return TEE_ERROR_BAD_FORMAT;

	memcpy(&header, segment, sizeof(header));
	version = header.version;
	if (version != PAS_MBN_VERSION_6) {
		EMSG("PAS auth: unsupported MBN version %#"PRIx32, version);
		return TEE_ERROR_BAD_FORMAT;
	}

	hdr_size = sizeof(header);
	if (segment_size < hdr_size)
		return TEE_ERROR_BAD_FORMAT;

	offset = hdr_size;
	res = pas_mbn_get_region(segment, segment_size, &offset,
				 header.qc_metadata_size, &qc_meta,
				 &qc_metadata_size);
	if (res)
		return res;

	res = pas_mbn_get_region(segment, segment_size, &offset,
				 header.oem_metadata_size, &oem_meta,
				 &oem_metadata_size);
	if (res)
		return res;

	if (!oem_meta)
		return TEE_ERROR_NO_DATA;

	if (oem_metadata_size < sizeof(struct pas_oem_metadata))
		return TEE_ERROR_BAD_FORMAT;

	memcpy(root_cert_sel, oem_meta +
	       offsetof(struct pas_oem_metadata, root_cert_sel),
	       sizeof(*root_cert_sel));

	return TEE_SUCCESS;
}

TEE_Result pas_meta_verify_elf_headers_hash(const uint8_t *meta_data,
					    size_t meta_data_size,
					    const uint8_t *hash_table,
					    uint32_t hash_len)
{
	uint8_t digest[TEE_SHA384_HASH_SIZE] = { };
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t digest_len = sizeof(digest);
	size_t phdr_entry_len = 0;
	size_t elf_hdr_len = 0;
	size_t phdr_count = 0;
	size_t hdr_len = 0;
	uint32_t algo = 0;

	if (!meta_data || !meta_data_size || !hash_table)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (hash_len) {
	case TEE_SHA256_HASH_SIZE:
		algo = TEE_ALG_SHA256;
		break;
	case TEE_SHA384_HASH_SIZE:
		algo = TEE_ALG_SHA384;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (meta_data_size < EI_NIDENT)
		return TEE_ERROR_BAD_FORMAT;

	if (meta_data[EI_MAG0] != ELFMAG0 || meta_data[EI_MAG1] != ELFMAG1 ||
	    meta_data[EI_MAG2] != ELFMAG2 || meta_data[EI_MAG3] != ELFMAG3)
		return TEE_ERROR_BAD_FORMAT;

	if (meta_data[EI_CLASS] == ELFCLASS64) {
		const Elf64_Ehdr *ehdr = (const void *)meta_data;

		if (meta_data_size < sizeof(*ehdr))
			return TEE_ERROR_BAD_FORMAT;
		elf_hdr_len = ehdr->e_ehsize;
		phdr_entry_len = ehdr->e_phentsize;
		phdr_count = ehdr->e_phnum;
	} else if (meta_data[EI_CLASS] == ELFCLASS32) {
		const Elf32_Ehdr *ehdr = (const void *)meta_data;

		if (meta_data_size < sizeof(*ehdr))
			return TEE_ERROR_BAD_FORMAT;
		elf_hdr_len = ehdr->e_ehsize;
		phdr_entry_len = ehdr->e_phentsize;
		phdr_count = ehdr->e_phnum;
	} else {
		return TEE_ERROR_BAD_FORMAT;
	}

	if (MUL_OVERFLOW(phdr_entry_len, phdr_count, &hdr_len) ||
	    ADD_OVERFLOW(hdr_len, elf_hdr_len, &hdr_len) ||
	    hdr_len > meta_data_size)
		return TEE_ERROR_BAD_FORMAT;

	res = TEE_AllocateOperation(&op, algo, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_DigestDoFinal(op, meta_data, hdr_len, digest, &digest_len);
	if (res != TEE_SUCCESS)
		goto out;

	if (digest_len != hash_len ||
	    consttime_memcmp(digest, hash_table, hash_len) != 0)
		res = TEE_ERROR_SECURITY;
	else
		res = TEE_SUCCESS;
out:
	TEE_FreeOperation(op);
	memzero_explicit(digest, sizeof(digest));

	return res;
}

TEE_Result pas_meta_get(const struct pas_hash_segment_info *hs,
			struct pas_oem_metadata *meta)
{
	const uint8_t *m = NULL;

	if (!hs || !meta)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hs->oem_meta || !hs->oem_meta_size)
		return TEE_ERROR_NO_DATA;

	if (hs->oem_meta_size < sizeof(struct pas_oem_metadata))
		return TEE_ERROR_BAD_FORMAT;

	m = hs->oem_meta;
	memcpy(meta, m, sizeof(*meta));

	return TEE_SUCCESS;
}

static void mask_meta_block(uint8_t *copy, size_t copy_len,
			    const uint8_t *block, size_t block_len,
			    const uint8_t *base)
{
	size_t off = 0;

	if (!block || !block_len)
		return;

	off = (size_t)(block - base);
	if (off < copy_len && block_len <= copy_len - off)
		memset(copy + off, 0, block_len);
}

static void zero_field(uint8_t *copy, size_t copy_len, size_t off)
{
	if (off + sizeof(uint32_t) <= copy_len)
		memset(copy + off, 0, sizeof(uint32_t));
}

TEE_Result
pas_meta_get_signed_region_copy(const struct pas_hash_segment_info *hs,
				uint8_t **out, size_t *out_len)
{
	uint8_t *copy = NULL;

	if (!hs || !hs->signed_region || !hs->signed_region_size || !out ||
	    !out_len)
		return TEE_ERROR_BAD_PARAMETERS;

	copy = TEE_Malloc(hs->signed_region_size, TEE_MALLOC_FILL_ZERO);
	if (!copy)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(copy, hs->signed_region, hs->signed_region_size);

	zero_field(copy, hs->signed_region_size,
		   offsetof(struct pas_mbn_header_v6, qc_signature_size));
	zero_field(copy, hs->signed_region_size,
		   offsetof(struct pas_mbn_header_v6, qc_cert_chain_size));
	mask_meta_block(copy, hs->signed_region_size, hs->qc_meta,
			hs->qc_meta_size, hs->signed_region);

	*out = copy;
	*out_len = hs->signed_region_size;

	return TEE_SUCCESS;
}
