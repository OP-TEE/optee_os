// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_mbn.h>
#include <stddef.h>
#include "pas_mbn_parser_common.h"
#include <util.h>

#include "pas_mbn_v7.h"

static TEE_Result pas_mbn_v7_parse(const uint8_t *segment,
				   size_t segment_size, uint32_t hash_len,
				   struct pas_mbn *mbn)
{
	struct pas_mbn_layout layout = {
		.version = PAS_MBN_VERSION_7,
		.header_size = sizeof(struct pas_mbn_header_v7),
	};

	static_assert(sizeof(struct pas_mbn_header_v7) == U(0x28));

	if (segment_size < sizeof(struct pas_mbn_header_v7))
		return TEE_ERROR_BAD_FORMAT;

	if (pas_mbn_read_u32(segment +
			 offsetof(struct pas_mbn_header_v7, version)) !=
	    PAS_MBN_VERSION_7)
		return TEE_ERROR_BAD_FORMAT;

	layout.common_meta_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, common_metadata_size));
	layout.qti_meta_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, qti_metadata_size));
	layout.oem_meta_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, oem_metadata_size));
	layout.hash_table_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, code_size));
	layout.qti_sig_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, qti_signature_size));
	layout.qti_certs_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, qti_cert_chain_size));
	layout.oem_sig_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, oem_signature_size));
	layout.oem_certs_size = pas_mbn_read_u32(segment + offsetof(
				struct pas_mbn_header_v7, oem_cert_chain_size));

	return pas_mbn_parse_layout(segment, segment_size, hash_len, &layout,
				    mbn);
}

static TEE_Result pas_mbn_v7_get_signed_data(const struct pas_mbn *mbn,
					     uint8_t **data,
					     size_t *data_len)
{
	return pas_mbn_copy_signed_data(mbn, offsetof(struct pas_mbn_header_v7,
						      qti_signature_size),
					offsetof(struct pas_mbn_header_v7,
						 qti_cert_chain_size),
					data, data_len);
}

const struct pas_mbn_ops pas_mbn_v7_ops = {
	.version = PAS_MBN_VERSION_7,
	.parse = pas_mbn_v7_parse,
	.get_signed_data = pas_mbn_v7_get_signed_data,
};
