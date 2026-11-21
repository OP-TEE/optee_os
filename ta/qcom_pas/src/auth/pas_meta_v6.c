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

#include "pas_mbn_v6.h"

#define PAS_META_V6_MAJOR_V0			U(0)
#define PAS_META_V6_MAJOR_V1			U(1)
#define PAS_META_V6_MINOR			U(0)

#define PAS_META_V6_FLAG_SOC_VERSION		U(1)
#define PAS_META_V6_FLAG_SERIAL_NUM		U(2)
#define PAS_META_V6_FLAG_OEM_ID_INDEPENDENT	U(3)
#define PAS_META_V6_FLAG_JTAG_ID		U(10)
#define PAS_META_V6_FLAG_MODEL_ID_INDEPENDENT	U(11)

#define PAS_META_V6_ROOT_REVOKE_SHIFT		U(4)
#define PAS_META_V6_UIE_KEY_SWITCH_SHIFT	U(6)
#define PAS_META_V6_DEBUG_SHIFT			U(8)
#define PAS_META_V6_OPTION_MASK			U(3)
#define PAS_META_V6_OPTION_MAX			U(2)
#define PAS_META_V6_OPTION_MATCH_SERIAL		U(2)

#define PAS_META_V6_SOC_VERSION_COUNT		U(12)
#define PAS_META_V6_SERIAL_NUM_COUNT		U(8)

struct pas_metadata_v6 {
	uint32_t major_version;
	uint32_t minor_version;
	uint32_t sw_id;
	uint32_t hw_id;
	uint32_t oem_id;
	uint32_t model_id;
	uint32_t secondary_sw_id;
	uint32_t flags;
	uint32_t soc_versions[PAS_META_V6_SOC_VERSION_COUNT];
	uint32_t serial_nums[PAS_META_V6_SERIAL_NUM_COUNT];
	uint32_t root_cert_sel;
	uint32_t anti_rollback;
};

static TEE_Result pas_meta_v6_get_metadata(const struct pas_mbn *mbn,
					   const uint8_t **metadata)
{
	static_assert(sizeof(struct pas_metadata_v6) == U(0x78));

	if (!mbn || !metadata)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!mbn->oem_meta || !mbn->oem_meta_size)
		return TEE_ERROR_NO_DATA;

	if (mbn->oem_meta_size < sizeof(struct pas_metadata_v6))
		return TEE_ERROR_BAD_FORMAT;

	*metadata = mbn->oem_meta;

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_read_u32(const struct pas_mbn *mbn,
				       size_t offset, uint32_t *value)
{
	const uint8_t *metadata = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!value)
		return TEE_ERROR_BAD_PARAMETERS;

	res = pas_meta_v6_get_metadata(mbn, &metadata);
	if (res)
		return res;

	*value = pas_mbn_read_u32(metadata + offset);

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_get_root_cert_sel(const uint8_t *segment,
						size_t segment_size,
						uint32_t *root_cert_sel)
{
	const uint8_t *metadata = NULL;
	const uint8_t *qc_metadata = NULL;
	size_t metadata_size = 0;
	size_t qc_metadata_size = 0;
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t offset = sizeof(struct pas_mbn_v6_header);
	size_t qc_size = 0;
	size_t oem_size = 0;

	if (!segment || !root_cert_sel)
		return TEE_ERROR_BAD_PARAMETERS;

	if (segment_size < sizeof(struct pas_mbn_v6_header))
		return TEE_ERROR_BAD_FORMAT;

	qc_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, qc_metadata_size));
	oem_size = pas_mbn_read_u32(segment +
		offsetof(struct pas_mbn_v6_header, oem_metadata_size));

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

	if (metadata_size < sizeof(struct pas_metadata_v6))
		return TEE_ERROR_BAD_FORMAT;

	*root_cert_sel = pas_mbn_read_u32(metadata +
		offsetof(struct pas_metadata_v6, root_cert_sel));

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_validate_version(const struct pas_mbn *mbn)
{
	uint32_t major = 0;
	uint32_t minor = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = pas_meta_v6_read_u32(mbn, offsetof(struct pas_metadata_v6,
						 major_version), &major);
	if (res)
		return res;

	res = pas_meta_v6_read_u32(mbn, offsetof(struct pas_metadata_v6,
						 minor_version), &minor);
	if (res)
		return res;

	if ((major == PAS_META_V6_MAJOR_V0 ||
	     major == PAS_META_V6_MAJOR_V1) && minor == PAS_META_V6_MINOR)
		return TEE_SUCCESS;

	EMSG("PAS auth: unsupported metadata version %#"PRIx32".%#"PRIx32,
	     major, minor);
	return TEE_ERROR_SECURITY;
}

static uint32_t pas_meta_v6_option(uint32_t flags, uint32_t shift)
{
	return (flags >> shift) & PAS_META_V6_OPTION_MASK;
}

static TEE_Result pas_meta_v6_validate_options(const struct pas_mbn *mbn)
{
	uint32_t flags = 0;
	TEE_Result res = pas_meta_v6_read_u32(mbn,
					      offsetof(struct pas_metadata_v6,
						       flags),
					      &flags);

	if (res)
		return res;

	if (pas_meta_v6_option(flags, PAS_META_V6_ROOT_REVOKE_SHIFT) <=
			PAS_META_V6_OPTION_MAX &&
	    pas_meta_v6_option(flags, PAS_META_V6_UIE_KEY_SWITCH_SHIFT) <=
			PAS_META_V6_OPTION_MAX &&
	    pas_meta_v6_option(flags, PAS_META_V6_DEBUG_SHIFT) <=
			PAS_META_V6_OPTION_MAX)
		return TEE_SUCCESS;

	EMSG("PAS auth: reserved metadata option value, flags=%#"PRIx32,
	     flags);
	return TEE_ERROR_SECURITY;
}

#define PAS_META_V6_GETTER(_name, _field) \
	static TEE_Result pas_meta_v6_get_##_name(const struct pas_mbn *mbn, \
						 uint32_t *value) \
	{ \
		return pas_meta_v6_read_u32(mbn, \
				offsetof(struct pas_metadata_v6, _field), \
				value); \
	}

PAS_META_V6_GETTER(sw_id, sw_id)
PAS_META_V6_GETTER(hw_id, hw_id)
PAS_META_V6_GETTER(oem_id, oem_id)
PAS_META_V6_GETTER(model_id, model_id)

static TEE_Result pas_meta_v6_get_flags(const struct pas_mbn *mbn,
					uint32_t *flags)
{
	return pas_meta_v6_read_u32(mbn,
				    offsetof(struct pas_metadata_v6, flags),
				    flags);
}

static TEE_Result pas_meta_v6_is_oem_id_bound(const struct pas_mbn *mbn,
					      bool *bound)
{
	uint32_t flags = 0;
	TEE_Result res = pas_meta_v6_get_flags(mbn, &flags);

	if (res)
		return res;

	*bound = !(flags & BIT32(PAS_META_V6_FLAG_OEM_ID_INDEPENDENT));

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_is_model_id_bound(const struct pas_mbn *mbn,
						bool *bound)
{
	uint32_t flags = 0;
	uint32_t major = 0;
	TEE_Result res = pas_meta_v6_get_flags(mbn, &flags);

	if (res)
		return res;

	res = pas_meta_v6_read_u32(mbn, offsetof(struct pas_metadata_v6,
						 major_version), &major);
	if (res)
		return res;

	if (major == PAS_META_V6_MAJOR_V0)
		*bound = !(flags & BIT32(PAS_META_V6_FLAG_OEM_ID_INDEPENDENT));
	else
		*bound = !(flags &
			   BIT32(PAS_META_V6_FLAG_MODEL_ID_INDEPENDENT));

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_is_jtag_id_bound(const struct pas_mbn *mbn,
					       bool *bound)
{
	uint32_t flags = 0;
	TEE_Result res = pas_meta_v6_get_flags(mbn, &flags);

	if (res)
		return res;

	*bound = flags & BIT32(PAS_META_V6_FLAG_JTAG_ID);

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_is_serial_bound(const struct pas_mbn *mbn,
					      bool *bound)
{
	static const uint32_t serial_gated_shifts[] = {
		PAS_META_V6_DEBUG_SHIFT,
		PAS_META_V6_ROOT_REVOKE_SHIFT,
		PAS_META_V6_UIE_KEY_SWITCH_SHIFT,
	};
	uint32_t flags = 0;
	TEE_Result res = pas_meta_v6_get_flags(mbn, &flags);
	size_t n = 0;

	if (res)
		return res;

	*bound = flags & BIT32(PAS_META_V6_FLAG_SERIAL_NUM);
	for (n = 0; !*bound && n < ARRAY_SIZE(serial_gated_shifts); n++)
		*bound = pas_meta_v6_option(flags, serial_gated_shifts[n]) ==
			 PAS_META_V6_OPTION_MATCH_SERIAL;

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_is_soc_version_bound(const struct pas_mbn *mbn,
						   bool *bound)
{
	uint32_t flags = 0;
	TEE_Result res = pas_meta_v6_get_flags(mbn, &flags);

	if (res)
		return res;

	*bound = flags & BIT32(PAS_META_V6_FLAG_SOC_VERSION);

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_serial_num_matches(const struct pas_mbn *mbn,
						 uint64_t serial_num,
						 bool *matches)
{
	const uint8_t *metadata = NULL;
	TEE_Result res = pas_meta_v6_get_metadata(mbn, &metadata);
	size_t n = 0;

	if (res)
		return res;

	*matches = false;
	for (n = 0; n < PAS_META_V6_SERIAL_NUM_COUNT; n++) {
		uint32_t value = pas_mbn_read_u32(metadata +
				offsetof(struct pas_metadata_v6, serial_nums) +
				n * sizeof(uint32_t));

		if (value && value == serial_num) {
			*matches = true;
			break;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result pas_meta_v6_soc_version_matches(const struct pas_mbn *mbn,
						  uint32_t soc_version,
						  bool *matches)
{
	const uint8_t *metadata = NULL;
	TEE_Result res = pas_meta_v6_get_metadata(mbn, &metadata);
	size_t n = 0;

	if (res)
		return res;

	*matches = false;
	for (n = 0; n < PAS_META_V6_SOC_VERSION_COUNT; n++) {
		uint32_t value = pas_mbn_read_u32(metadata +
				offsetof(struct pas_metadata_v6, soc_versions) +
				n * sizeof(uint32_t));

		if (value == soc_version) {
			*matches = true;
			break;
		}
	}

	return TEE_SUCCESS;
}

const struct pas_meta_ops pas_meta_v6_ops = {
	.version = PAS_MBN_VERSION_6,
	.get_root_cert_sel = pas_meta_v6_get_root_cert_sel,
	.validate_version = pas_meta_v6_validate_version,
	.validate_options = pas_meta_v6_validate_options,
	.get_sw_id = pas_meta_v6_get_sw_id,
	.get_hw_id = pas_meta_v6_get_hw_id,
	.get_oem_id = pas_meta_v6_get_oem_id,
	.get_model_id = pas_meta_v6_get_model_id,
	.is_oem_id_bound = pas_meta_v6_is_oem_id_bound,
	.is_model_id_bound = pas_meta_v6_is_model_id_bound,
	.is_jtag_id_bound = pas_meta_v6_is_jtag_id_bound,
	.is_serial_bound = pas_meta_v6_is_serial_bound,
	.is_soc_version_bound = pas_meta_v6_is_soc_version_bound,
	.serial_num_matches = pas_meta_v6_serial_num_matches,
	.soc_version_matches = pas_meta_v6_soc_version_matches,
};
