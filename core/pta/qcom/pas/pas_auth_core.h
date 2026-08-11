/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PAS_AUTH_CORE_H
#define __PAS_AUTH_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <types_ext.h>

#define PAS_AUTH_CORE_MAX_HASH_SIZE	48U

struct pas_auth_core_ctx {
	uint32_t hash_algo;
	size_t hash_len;
	const uint8_t *hash_table;
	uint32_t num_entries;
	const uint8_t *metadata;
	size_t metadata_len;
	uint8_t *fw;
	size_t fw_size;
};

TEE_Result pas_auth_core_verify_segments(const struct pas_auth_core_ctx *ctx);

#endif /* __PAS_AUTH_CORE_H */
