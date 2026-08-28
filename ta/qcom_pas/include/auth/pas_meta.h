/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __AUTH_PAS_META_H
#define __AUTH_PAS_META_H

#include <auth/pas_mbn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

#define PAS_META_FLAG_IN_USE_SOC_HW_VERSION	1
#define PAS_META_FLAG_USE_SERIAL_NUMBER		2
#define PAS_META_FLAG_OEM_ID_INDEPENDENT	3
#define PAS_META_FLAG_IN_USE_JTAG_ID		10
#define PAS_META_FLAG_MODEL_ID_INDEPENDENT	11

#define PAS_META_FLAG_ROOT_REVOKE_ACTIVATE_SHIFT	4
#define PAS_META_FLAG_UIE_KEY_SWITCH_SHIFT		6
#define PAS_META_FLAG_DEBUG_SHIFT			8
#define PAS_META_OPTION_MASK				3U
#define PAS_META_OPTION_MAX				2U
#define PAS_META_OPTION_ENABLE_SN			2U

struct pas_md_slot {
	void *meta_data;
	size_t meta_data_size;
	uint32_t pas_id;
	bool in_use;
	struct pas_hash_segment_info mbn;
	bool ready;
};

struct pas_oem_metadata {
	uint32_t major;
	uint32_t minor;
	uint32_t sw_id;
	uint32_t hw_id;
	uint32_t oem_id;
	uint32_t model_id;
	uint32_t secondary_sw_id;
	uint32_t flags;
	uint32_t soc_vers[12];
	uint32_t serial_num[8];
	uint32_t root_cert_sel;
	uint32_t anti_rollback;
};

TEE_Result pas_meta_get_version(const uint8_t *meta_data,
				size_t meta_data_size, uint32_t *version);

TEE_Result pas_meta_segment_hash_len(const uint8_t *meta_data,
				     size_t meta_data_size,
				     uint32_t *hash_len);

TEE_Result pas_meta_get_root_cert_sel(const uint8_t *meta_data,
				      size_t meta_data_size,
				      uint32_t *root_cert_sel);

TEE_Result pas_meta_verify_elf_headers_hash(const uint8_t *meta_data,
					    size_t meta_data_size,
					    const uint8_t *hash_table,
					    uint32_t hash_len);

TEE_Result pas_meta_get(const struct pas_hash_segment_info *hs,
			struct pas_oem_metadata *meta);

TEE_Result
pas_meta_get_signed_region_copy(const struct pas_hash_segment_info *hs,
				uint8_t **out, size_t *out_len);

#endif /* __AUTH_PAS_META_H */
