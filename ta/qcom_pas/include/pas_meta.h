/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_META_H
#define __PAS_META_H

#include <pas_mbn_parser.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

TEE_Result pas_meta_get_version(const uint8_t *meta_data,
				size_t meta_data_size, uint32_t *version);

TEE_Result pas_meta_segment_hash_len(const uint8_t *meta_data,
				     size_t meta_data_size,
				     uint32_t *hash_len);

#endif /* __PAS_META_H */
