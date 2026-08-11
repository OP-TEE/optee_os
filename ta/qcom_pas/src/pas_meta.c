// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <pas_mbn_parser_priv.h>
#include <pas_meta.h>
#include <tee_internal_api.h>
#include <utee_defines.h>

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
