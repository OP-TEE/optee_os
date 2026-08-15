// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_mbn.h>
#include <auth/pas_meta.h>
#include <elf32.h>
#include <elf64.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api.h>
#include <utee_defines.h>
#include <util.h>

#define OEM_META_OFF_MAJOR		0
#define OEM_META_OFF_MINOR		1
#define OEM_META_OFF_SW_ID		2
#define OEM_META_OFF_HW_ID		3
#define OEM_META_OFF_OEM_ID		4
#define OEM_META_OFF_MODEL_ID		5
#define OEM_META_OFF_SECONDARY_SW_ID	6
#define OEM_META_OFF_FLAGS		7
#define OEM_META_OFF_SOC_VERS		8
#define OEM_META_NUM_SOC_VERS		12
#define OEM_META_OFF_SERIAL_NUM	(OEM_META_OFF_SOC_VERS + OEM_META_NUM_SOC_VERS)
#define OEM_META_NUM_SERIAL_NUM	8
#define OEM_META_OFF_ANTI_ROLLBACK	29
#define OEM_META_OFF_ROOT_CERT_SEL	28
#define OEM_META_MIN_WORDS		(OEM_META_OFF_ANTI_ROLLBACK + 1)

TEE_Result pas_meta_get_version(const uint8_t *meta_data,
				size_t meta_data_size, uint32_t *version)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *seg = NULL;
	size_t seg_size = 0;

	if (!meta_data || !meta_data_size || !version)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_mbn_locate(meta_data, meta_data_size, &seg, &seg_size);
	if (res)
		return res;

	if (seg_size < MBN_OFF_VERSION + sizeof(uint32_t))
		return TEE_ERROR_BAD_FORMAT;

	*version = pas_mbn_read_u32(seg + MBN_OFF_VERSION);

	return TEE_SUCCESS;
}

TEE_Result pas_meta_segment_hash_len(const uint8_t *meta_data,
				     size_t meta_data_size, uint32_t *hash_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t version = 0;

	if (!hash_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_get_version(meta_data, meta_data_size, &version);
	if (res)
		return res;

	switch (version) {
	case PAS_MBN_VERSION_6:
		*hash_len = TEE_SHA384_HASH_SIZE;
		return TEE_SUCCESS;
	default:
		EMSG("PAS auth: unsupported MBN version %#"PRIx32, version);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result pas_meta_get_root_cert_sel(const uint8_t *meta_data,
				      size_t meta_data_size,
				      uint32_t *root_cert_sel)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint8_t *oem_meta = NULL;
	const uint8_t *qc_meta = NULL;
	const uint8_t *segment = NULL;
	uint32_t oem_meta_size = 0;
	uint32_t qc_meta_size = 0;
	size_t segment_size = 0;
	size_t oem_meta_len = 0;
	size_t qc_meta_len = 0;
	uint32_t version = 0;
	size_t hdr_size = 0;
	size_t offset = 0;

	if (!meta_data || !meta_data_size || !root_cert_sel)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_mbn_locate(meta_data, meta_data_size, &segment,
			     &segment_size);
	if (res)
		return res;

	if (segment_size < MBN_HDR_SIZE_V6)
		return TEE_ERROR_BAD_FORMAT;

	version = pas_mbn_read_u32(segment + MBN_OFF_VERSION);
	if (version != PAS_MBN_VERSION_6) {
		EMSG("PAS auth: unsupported MBN version %#"PRIx32, version);
		return TEE_ERROR_BAD_FORMAT;
	}

	hdr_size = MBN_HDR_SIZE_V6;
	if (segment_size < hdr_size)
		return TEE_ERROR_BAD_FORMAT;

	qc_meta_size = pas_mbn_read_u32(segment + MBN_OFF_QC_META_SIZE);
	oem_meta_size = pas_mbn_read_u32(segment + MBN_OFF_OEM_META_SIZE);

	offset = hdr_size;
	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     qc_meta_size, &qc_meta, &qc_meta_len);
	if (res)
		return res;
	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     oem_meta_size, &oem_meta, &oem_meta_len);
	if (res)
		return res;

	if (!oem_meta)
		return TEE_ERROR_NO_DATA;

	if (oem_meta_len < OEM_META_MIN_WORDS * sizeof(uint32_t))
		return TEE_ERROR_BAD_FORMAT;

	*root_cert_sel = pas_mbn_read_u32(oem_meta +
					  OEM_META_OFF_ROOT_CERT_SEL *
					  sizeof(uint32_t));

	return TEE_SUCCESS;
}

TEE_Result pas_meta_verify_preamble(const uint8_t *meta_data,
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

TEE_Result pas_meta_get(const struct pas_mbn *hs,
			struct pas_oem_metadata *meta)
{
	const uint8_t *m = NULL;
	size_t i = 0;

	if (!hs || !meta)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hs->oem_meta || !hs->oem_meta_size)
		return TEE_ERROR_NO_DATA;

	if (hs->oem_meta_size < OEM_META_MIN_WORDS * sizeof(uint32_t))
		return TEE_ERROR_BAD_FORMAT;

	m = hs->oem_meta;
	meta->major = pas_mbn_read_u32(m + OEM_META_OFF_MAJOR *
					   sizeof(uint32_t));
	meta->minor = pas_mbn_read_u32(m + OEM_META_OFF_MINOR *
					   sizeof(uint32_t));
	meta->sw_id = pas_mbn_read_u32(m + OEM_META_OFF_SW_ID *
					   sizeof(uint32_t));
	meta->hw_id = pas_mbn_read_u32(m + OEM_META_OFF_HW_ID *
					   sizeof(uint32_t));
	meta->oem_id = pas_mbn_read_u32(m + OEM_META_OFF_OEM_ID *
					    sizeof(uint32_t));
	meta->model_id = pas_mbn_read_u32(m + OEM_META_OFF_MODEL_ID *
					      sizeof(uint32_t));
	meta->secondary_sw_id =
		pas_mbn_read_u32(m + OEM_META_OFF_SECONDARY_SW_ID *
				     sizeof(uint32_t));
	meta->flags = pas_mbn_read_u32(m + OEM_META_OFF_FLAGS *
					   sizeof(uint32_t));
	for (i = 0; i < OEM_META_NUM_SOC_VERS; i++)
		meta->soc_vers[i] = pas_mbn_read_u32(m +
						     (OEM_META_OFF_SOC_VERS +
						      i) *
						     sizeof(uint32_t));
	for (i = 0; i < OEM_META_NUM_SERIAL_NUM; i++)
		meta->serial_num[i] =
			pas_mbn_read_u32(m + (OEM_META_OFF_SERIAL_NUM + i) *
					     sizeof(uint32_t));
	meta->root_cert_sel = pas_mbn_read_u32(m + OEM_META_OFF_ROOT_CERT_SEL *
						   sizeof(uint32_t));
	meta->anti_rollback = pas_mbn_read_u32(m +
						OEM_META_OFF_ANTI_ROLLBACK *
						sizeof(uint32_t));

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

TEE_Result pas_meta_get_signed_region_copy(const struct pas_mbn *hs,
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

	zero_field(copy, hs->signed_region_size, MBN_OFF_QC_SIG_SIZE);
	zero_field(copy, hs->signed_region_size, MBN_OFF_QC_CERT_SIZE);
	mask_meta_block(copy, hs->signed_region_size, hs->qti_meta,
			hs->qti_meta_size, hs->signed_region);

	*out = copy;
	*out_len = hs->signed_region_size;

	return TEE_SUCCESS;
}
