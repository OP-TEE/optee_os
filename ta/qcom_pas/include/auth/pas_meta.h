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

TEE_Result pas_meta_get_version(const uint8_t *meta_data,
				size_t meta_data_size, uint32_t *version);

TEE_Result pas_meta_segment_hash_len(const uint8_t *meta_data,
				     size_t meta_data_size,
				     uint32_t *hash_len);

#endif /* __AUTH_PAS_META_H */
