// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_mbn.h>
#include <stddef.h>
#include "pas_mbn_parser_common.h"
#include <util.h>

#include "pas_mbn_v6.h"

static TEE_Result pas_mbn_v6_parse(const uint8_t *segment,
				   size_t segment_size, uint32_t hash_len,
				   struct pas_mbn *mbn)
{
	struct pas_mbn_layout layout = {
		.version = PAS_MBN_VERSION_6,
		.header_size = sizeof(struct pas_mbn_v6_header),
	};

	static_assert(sizeof(struct pas_mbn_v6_header) == U(0x30));

	if (segment_size < sizeof(struct pas_mbn_v6_header))
		return TEE_ERROR_BAD_FORMAT;

	if (pas_mbn_read_u32(segment +
			 offsetof(struct pas_mbn_v6_header, version)) !=
	    PAS_MBN_VERSION_6)
		return TEE_ERROR_BAD_FORMAT;

	layout.qc_sig_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, qc_signature_size));
	layout.qc_certs_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, qc_cert_chain_size));
	layout.hash_table_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, code_size));
	layout.oem_sig_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, oem_signature_size));
	layout.oem_certs_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, oem_cert_chain_size));
	layout.qc_meta_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, qc_metadata_size));
	layout.oem_meta_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, oem_metadata_size));

	return pas_mbn_parse_layout(segment, segment_size, hash_len, &layout,
				    mbn);
}

static TEE_Result pas_mbn_v6_get_signed_data(const struct pas_mbn *mbn,
					     uint8_t **data,
					     size_t *data_len)
{
	return pas_mbn_copy_signed_data(mbn, offsetof(struct pas_mbn_v6_header,
						      qc_signature_size),
					offsetof(struct pas_mbn_v6_header,
						 qc_cert_chain_size),
					data, data_len);
}

const struct pas_mbn_ops pas_mbn_v6_ops = {
	.version = PAS_MBN_VERSION_6,
	.parse = pas_mbn_v6_parse,
	.get_signed_data = pas_mbn_v6_get_signed_data,
};
