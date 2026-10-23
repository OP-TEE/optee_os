// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <auth/pas_mbn.h>
#include <inttypes.h>
#include "pas_mbn_parser_common.h"
#include "pas_meta_common.h"
#include <stddef.h>
#include <tee_internal_api.h>
#include <util.h>

#include "pas_mbn_v7.h"

#define PAS_META_V7_MAJOR_V2			U(2)
#define PAS_META_V7_MAJOR_V3			U(3)
#define PAS_META_V7_MINOR			U(0)

#define PAS_META_V7_SOC_VERSION_BOUND_SHIFT	U(0)
#define PAS_META_V7_JTAG_ID_BOUND_SHIFT		U(4)
#define PAS_META_V7_SERIAL_BOUND_SHIFT		U(6)
#define PAS_META_V7_OEM_ID_BOUND_SHIFT		U(8)
#define PAS_META_V7_MODEL_ID_BOUND_SHIFT	U(10)
#define PAS_META_V7_MAX_FLAG_SHIFT		U(20)

#define PAS_META_V7_SOC_VERSION_COUNT		U(12)
#define PAS_META_V7_SERIAL_NUM_COUNT		U(8)

struct pas_common_metadata_v7 {
	uint32_t major_version;
	uint32_t minor_version;
	uint32_t sw_id;
	uint32_t secondary_sw_id;
	uint32_t hash_table_algo;
	uint32_t measurement_register_target;
};

struct pas_metadata_v7 {
	uint32_t major_version;
	uint32_t minor_version;
	uint32_t anti_rollback;
	uint32_t root_cert_sel;
	uint32_t soc_versions[PAS_META_V7_SOC_VERSION_COUNT];
	uint32_t product_segment_id;
	uint32_t hw_id;
	uint64_t serial_nums[PAS_META_V7_SERIAL_NUM_COUNT];
	uint32_t oem_id;
	uint32_t model_id;
	uint32_t soc_lifecycle_state;
	uint32_t oem_lifecycle_state;
	uint32_t oem_root_hash_algo;
	uint8_t oem_root_hash[64];
	uint32_t flags;
};

static TEE_Result pas_meta_v7_get_metadata(const struct pas_mbn *mbn,
					   const uint8_t **metadata)
{
	static_assert(sizeof(struct pas_metadata_v7) == U(0xe0));

	if (!mbn || !metadata)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!mbn->oem_meta || !mbn->oem_meta_size)
		return TEE_ERROR_NO_DATA;

	if (mbn->oem_meta_size < sizeof(struct pas_metadata_v7))
		return TEE_ERROR_BAD_FORMAT;

	*metadata = mbn->oem_meta;

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v7_get_common_metadata(const struct pas_mbn *mbn,
						  const uint8_t **metadata)
{
	static_assert(sizeof(struct pas_common_metadata_v7) == U(0x18));

	if (!mbn || !metadata)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!mbn->common_meta ||
	    mbn->common_meta_size < sizeof(struct pas_common_metadata_v7))
		return TEE_ERROR_BAD_FORMAT;

	*metadata = mbn->common_meta;

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v7_read_u32(const struct pas_mbn *mbn,
				       size_t offset, uint32_t *value)
{
	const uint8_t *metadata = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!value)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_v7_get_metadata(mbn, &metadata);
	if (res)
		return res;

	*value = pas_mbn_read_u32(metadata + offset);

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v7_get_root_cert_sel(const uint8_t *segment,
						size_t segment_size,
						uint32_t *root_cert_sel)
{
	const uint8_t *common_metadata = NULL;
	const uint8_t *qc_metadata = NULL;
	const uint8_t *metadata = NULL;
	size_t common_metadata_size = 0;
	size_t qc_metadata_size = 0;
	size_t metadata_size = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t offset = sizeof(struct pas_mbn_header_v7);
	size_t common_size = 0;
	size_t qc_size = 0;
	size_t oem_size = 0;

	if (!segment || !root_cert_sel)
		return TEE_ERROR_BAD_PARAMETERS;

	if (segment_size < sizeof(struct pas_mbn_header_v7))
		return TEE_ERROR_BAD_FORMAT;

	common_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_header_v7, common_metadata_size));
	qc_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_header_v7, qc_metadata_size));
	oem_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_header_v7, oem_metadata_size));

	res = pas_mbn_reserve_region(segment, segment_size, &offset,
				     common_size, &common_metadata,
				     &common_metadata_size);
	if (res)
		return res;

	res = pas_mbn_reserve_region(segment, segment_size, &offset, qc_size,
				     &qc_metadata, &qc_metadata_size);
	if (res)
		return res;

	res = pas_mbn_reserve_region(segment, segment_size, &offset, oem_size,
				     &metadata, &metadata_size);
	if (res)
		return res;

	if (!metadata)
		return TEE_ERROR_NO_DATA;

	if (metadata_size < sizeof(struct pas_metadata_v7))
		return TEE_ERROR_BAD_FORMAT;

	*root_cert_sel = pas_mbn_read_u32(metadata +
		offsetof(struct pas_metadata_v7, root_cert_sel));

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v7_validate_version(const struct pas_mbn *mbn)
{
	const uint8_t *common_metadata = NULL;
	uint32_t major = 0;
	uint32_t minor = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = pas_meta_v7_get_common_metadata(mbn, &common_metadata);
	if (res)
		return res;

	res = pas_meta_v7_read_u32(mbn, offsetof(struct pas_metadata_v7,
						 major_version), &major);
	if (res)
		return res;

	res = pas_meta_v7_read_u32(mbn, offsetof(struct pas_metadata_v7,
						 minor_version), &minor);
	if (res)
		return res;

	if ((major == PAS_META_V7_MAJOR_V2 ||
	     major == PAS_META_V7_MAJOR_V3) && minor == PAS_META_V7_MINOR)
		return TEE_SUCCESS;

	EMSG("PAS auth: unsupported metadata version %#"PRIx32".%#"PRIx32,
	     major, minor);
	return TEE_ERROR_SECURITY;
}

static bool pas_meta_v7_flag_bound(uint32_t flags, uint32_t shift)
{
	return ((flags >> (shift + 1)) & U(1)) &&
	       !((flags >> shift) & U(1));
}

static TEE_Result pas_meta_v7_get_flags(const struct pas_mbn *mbn,
					uint32_t *flags)
{
	return pas_meta_v7_read_u32(mbn,
				    offsetof(struct pas_metadata_v7, flags),
				    flags);
}

static TEE_Result pas_meta_v7_validate_options(const struct pas_mbn *mbn)
{
	uint32_t flags = 0;
	uint32_t shift = 0;
	TEE_Result res = pas_meta_v7_get_flags(mbn, &flags);

	if (res)
		return res;

	for (shift = 0; shift <= PAS_META_V7_MAX_FLAG_SHIFT; shift += 2) {
		uint32_t value = (flags >> shift) & U(3);

		if (value != U(1) && value != U(2))
			return TEE_ERROR_SECURITY;
	}

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v7_get_sw_id(const struct pas_mbn *mbn,
					uint32_t *sw_id)
{
	const uint8_t *metadata = NULL;
	TEE_Result res = pas_meta_v7_get_common_metadata(mbn, &metadata);

	if (res)
		return res;

	*sw_id = pas_mbn_read_u32(metadata +
			offsetof(struct pas_common_metadata_v7, sw_id));

	return TEE_SUCCESS;
}

#define PAS_META_V7_GETTER(_name, _field) \
	static TEE_Result pas_meta_v7_get_##_name(const struct pas_mbn *mbn, \
						 uint32_t *value) \
	{ \
		return pas_meta_v7_read_u32(mbn, \
				offsetof(struct pas_metadata_v7, _field), \
				value); \
	}

PAS_META_V7_GETTER(hw_id, hw_id)
PAS_META_V7_GETTER(oem_id, oem_id)
PAS_META_V7_GETTER(model_id, model_id)

static TEE_Result pas_meta_v7_is_bound(const struct pas_mbn *mbn,
				       uint32_t shift, bool *bound)
{
	uint32_t flags = 0;
	TEE_Result res = pas_meta_v7_get_flags(mbn, &flags);

	if (res)
		return res;

	*bound = pas_meta_v7_flag_bound(flags, shift);

	return TEE_SUCCESS;
}

#define PAS_META_V7_BOUND_GETTER(_name, _shift) \
	static TEE_Result pas_meta_v7_is_##_name##_bound( \
						const struct pas_mbn *mbn, \
						bool *bound) \
	{ \
		return pas_meta_v7_is_bound(mbn, _shift, bound); \
	}

PAS_META_V7_BOUND_GETTER(oem_id, PAS_META_V7_OEM_ID_BOUND_SHIFT)
PAS_META_V7_BOUND_GETTER(model_id, PAS_META_V7_MODEL_ID_BOUND_SHIFT)
PAS_META_V7_BOUND_GETTER(jtag_id, PAS_META_V7_JTAG_ID_BOUND_SHIFT)
PAS_META_V7_BOUND_GETTER(serial, PAS_META_V7_SERIAL_BOUND_SHIFT)
PAS_META_V7_BOUND_GETTER(soc_version, PAS_META_V7_SOC_VERSION_BOUND_SHIFT)

static TEE_Result pas_meta_v7_serial_num_matches(const struct pas_mbn *mbn,
						 uint64_t serial_num,
						 bool *matches)
{
	const uint8_t *metadata = NULL;
	TEE_Result res = pas_meta_v7_get_metadata(mbn, &metadata);
	size_t n = 0;

	if (res)
		return res;

	*matches = false;
	for (n = 0; n < PAS_META_V7_SERIAL_NUM_COUNT; n++) {
		uint64_t value = pas_mbn_read_u64(metadata +
				offsetof(struct pas_metadata_v7, serial_nums) +
				n * sizeof(uint64_t));

		if (value && value == serial_num) {
			*matches = true;
			break;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v7_soc_version_matches(const struct pas_mbn *mbn,
						  uint32_t soc_version,
						  bool *matches)
{
	const uint8_t *metadata = NULL;
	TEE_Result res = pas_meta_v7_get_metadata(mbn, &metadata);
	size_t n = 0;

	if (res)
		return res;

	*matches = false;
	for (n = 0; n < PAS_META_V7_SOC_VERSION_COUNT; n++) {
		uint32_t value = pas_mbn_read_u32(metadata +
				offsetof(struct pas_metadata_v7, soc_versions) +
				n * sizeof(uint32_t));

		if (value == soc_version) {
			*matches = true;
			break;
		}
	}

	return TEE_SUCCESS;
}

const struct pas_meta_ops pas_meta_v7_ops = {
	.version = PAS_MBN_VERSION_7,
	.get_root_cert_sel = pas_meta_v7_get_root_cert_sel,
	.validate_version = pas_meta_v7_validate_version,
	.validate_options = pas_meta_v7_validate_options,
	.get_sw_id = pas_meta_v7_get_sw_id,
	.get_hw_id = pas_meta_v7_get_hw_id,
	.get_oem_id = pas_meta_v7_get_oem_id,
	.get_model_id = pas_meta_v7_get_model_id,
	.is_oem_id_bound = pas_meta_v7_is_oem_id_bound,
	.is_model_id_bound = pas_meta_v7_is_model_id_bound,
	.is_jtag_id_bound = pas_meta_v7_is_jtag_id_bound,
	.is_serial_bound = pas_meta_v7_is_serial_bound,
	.is_soc_version_bound = pas_meta_v7_is_soc_version_bound,
	.serial_num_matches = pas_meta_v7_serial_num_matches,
	.soc_version_matches = pas_meta_v7_soc_version_matches,
};
