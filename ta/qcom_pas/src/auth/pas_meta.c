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

#include "pas_mbn_parser_common.h"
#include "pas_meta_common.h"

static const struct pas_meta_ops *pas_meta_get_ops(uint32_t version)
{
	switch (version) {
	case PAS_MBN_VERSION_6:
		return &pas_meta_v6_ops;
	default:
		return NULL;
	}
}

static TEE_Result pas_meta_get_mbn_ops(const struct pas_mbn *mbn,
				       const struct pas_meta_ops **ops)
{
	if (!mbn || !ops)
		return TEE_ERROR_BAD_PARAMETERS;

	*ops = pas_meta_get_ops(mbn->version);
	if (!*ops)
		return TEE_ERROR_BAD_FORMAT;

	return TEE_SUCCESS;
}

TEE_Result pas_meta_get_root_cert_sel(const uint8_t *meta_data,
				      size_t meta_data_size,
				      uint32_t *root_cert_sel)
{
	const struct pas_meta_ops *ops = NULL;
	const uint8_t *segment = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t segment_size = 0;
	uint32_t version = 0;

	if (!meta_data || !meta_data_size || !root_cert_sel)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_mbn_locate(meta_data, meta_data_size, &segment,
			     &segment_size);
	if (res)
		return res;

	res = pas_mbn_get_version(segment, segment_size, &version);
	if (res)
		return res;

	ops = pas_meta_get_ops(version);
	if (!ops) {
		EMSG("PAS auth: unsupported MBN version %#"PRIx32, version);
		return TEE_ERROR_BAD_FORMAT;
	}

	return ops->get_root_cert_sel(segment, segment_size, root_cert_sel);
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

TEE_Result pas_meta_validate_version(const struct pas_mbn *mbn)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = pas_meta_get_mbn_ops(mbn, &ops);

	if (res)
		return res;

	return ops->validate_version(mbn);
}

TEE_Result pas_meta_validate_options(const struct pas_mbn *mbn)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = pas_meta_get_mbn_ops(mbn, &ops);

	if (res)
		return res;

	return ops->validate_options(mbn);
}

TEE_Result pas_meta_get_sw_id(const struct pas_mbn *mbn, uint32_t *sw_id)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!sw_id)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_get_mbn_ops(mbn, &ops);
	if (res)
		return res;

	return ops->get_sw_id(mbn, sw_id);
}

TEE_Result pas_meta_get_hw_id(const struct pas_mbn *mbn, uint32_t *hw_id)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!hw_id)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_get_mbn_ops(mbn, &ops);
	if (res)
		return res;

	return ops->get_hw_id(mbn, hw_id);
}

TEE_Result pas_meta_get_oem_id(const struct pas_mbn *mbn, uint32_t *oem_id)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!oem_id)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_get_mbn_ops(mbn, &ops);
	if (res)
		return res;

	return ops->get_oem_id(mbn, oem_id);
}

TEE_Result pas_meta_get_model_id(const struct pas_mbn *mbn,
				 uint32_t *model_id)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!model_id)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_get_mbn_ops(mbn, &ops);
	if (res)
		return res;

	return ops->get_model_id(mbn, model_id);
}

#define PAS_META_BOUND_GETTER(_name) \
	TEE_Result pas_meta_is_##_name##_bound(const struct pas_mbn *mbn, \
					      bool *bound) \
	{ \
		const struct pas_meta_ops *ops = NULL; \
		TEE_Result res = TEE_ERROR_GENERIC; \
		if (!bound) \
			return TEE_ERROR_BAD_PARAMETERS; \
		res = pas_meta_get_mbn_ops(mbn, &ops); \
		if (res) \
			return res; \
		return ops->is_##_name##_bound(mbn, bound); \
	}

PAS_META_BOUND_GETTER(oem_id)
PAS_META_BOUND_GETTER(model_id)
PAS_META_BOUND_GETTER(jtag_id)
PAS_META_BOUND_GETTER(serial)
PAS_META_BOUND_GETTER(soc_version)

TEE_Result pas_meta_serial_num_matches(const struct pas_mbn *mbn,
				       uint64_t serial_num, bool *matches)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!matches)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_get_mbn_ops(mbn, &ops);
	if (res)
		return res;

	return ops->serial_num_matches(mbn, serial_num, matches);
}

TEE_Result pas_meta_soc_version_matches(const struct pas_mbn *mbn,
					uint32_t soc_version, bool *matches)
{
	const struct pas_meta_ops *ops = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!matches)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_get_mbn_ops(mbn, &ops);
	if (res)
		return res;

	return ops->soc_version_matches(mbn, soc_version, matches);
}
