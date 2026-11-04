/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_META_COMMON_H
#define __PAS_META_COMMON_H

#include <auth/pas_mbn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

struct pas_meta_ops {
	uint32_t version;
	TEE_Result (*get_root_cert_sel)(const uint8_t *segment,
					size_t segment_size,
					uint32_t *root_cert_sel);
	TEE_Result (*validate_version)(const struct pas_mbn *mbn);
	TEE_Result (*validate_options)(const struct pas_mbn *mbn);
	TEE_Result (*get_sw_id)(const struct pas_mbn *mbn, uint32_t *sw_id);
	TEE_Result (*get_hw_id)(const struct pas_mbn *mbn, uint32_t *hw_id);
	TEE_Result (*get_oem_id)(const struct pas_mbn *mbn, uint32_t *oem_id);
	TEE_Result (*get_model_id)(const struct pas_mbn *mbn,
				   uint32_t *model_id);
	TEE_Result (*is_oem_id_bound)(const struct pas_mbn *mbn, bool *bound);
	TEE_Result (*is_model_id_bound)(const struct pas_mbn *mbn, bool *bound);
	TEE_Result (*is_jtag_id_bound)(const struct pas_mbn *mbn, bool *bound);
	TEE_Result (*is_serial_bound)(const struct pas_mbn *mbn, bool *bound);
	TEE_Result (*is_soc_version_bound)(const struct pas_mbn *mbn,
					   bool *bound);
	TEE_Result (*serial_num_matches)(const struct pas_mbn *mbn,
					 uint64_t serial_num, bool *matches);
	TEE_Result (*soc_version_matches)(const struct pas_mbn *mbn,
					  uint32_t soc_version, bool *matches);
};

extern const struct pas_meta_ops pas_meta_v6_ops;

#endif /* __PAS_META_COMMON_H */
