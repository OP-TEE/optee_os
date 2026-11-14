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

struct pas_md_slot {
	void *meta_data;
	size_t meta_data_size;
	uint32_t pas_id;
	bool in_use;
	struct pas_mbn mbn;
	bool ready;
};
TEE_Result pas_meta_get_root_cert_sel(const uint8_t *meta_data,
				      size_t meta_data_size,
				      uint32_t *root_cert_sel);

TEE_Result pas_meta_verify_elf_headers_hash(const uint8_t *meta_data,
					    size_t meta_data_size,
					    const uint8_t *hash_table,
					    uint32_t hash_len);

TEE_Result pas_meta_validate_version(const struct pas_mbn *mbn);
TEE_Result pas_meta_validate_options(const struct pas_mbn *mbn);

TEE_Result pas_meta_get_sw_id(const struct pas_mbn *mbn, uint32_t *sw_id);
TEE_Result pas_meta_get_hw_id(const struct pas_mbn *mbn, uint32_t *hw_id);
TEE_Result pas_meta_get_oem_id(const struct pas_mbn *mbn, uint32_t *oem_id);
TEE_Result pas_meta_get_model_id(const struct pas_mbn *mbn,
				 uint32_t *model_id);

TEE_Result pas_meta_is_oem_id_bound(const struct pas_mbn *mbn, bool *bound);
TEE_Result pas_meta_is_model_id_bound(const struct pas_mbn *mbn, bool *bound);
TEE_Result pas_meta_is_jtag_id_bound(const struct pas_mbn *mbn, bool *bound);
TEE_Result pas_meta_is_serial_bound(const struct pas_mbn *mbn, bool *bound);
TEE_Result pas_meta_is_soc_version_bound(const struct pas_mbn *mbn,
					 bool *bound);

TEE_Result pas_meta_serial_num_matches(const struct pas_mbn *mbn,
				       uint64_t serial_num, bool *matches);
TEE_Result pas_meta_soc_version_matches(const struct pas_mbn *mbn,
					uint32_t soc_version, bool *matches);

#endif /* __AUTH_PAS_META_H */
