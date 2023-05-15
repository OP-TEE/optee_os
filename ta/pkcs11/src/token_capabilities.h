/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef TOKEN_CAPABILITIES_H
#define TOKEN_CAPABILITIES_H

#include <pkcs11_ta.h>
#include <stdbool.h>
#include <stdint.h>

bool mechanism_flags_complies_pkcs11(uint32_t mechanism_type, uint32_t flags);

bool mechanism_is_one_shot_only(uint32_t mechanism_type);

bool mechanism_is_valid(enum pkcs11_mechanism_id id);

#if CFG_TEE_TA_LOG_LEVEL > 0
const char *mechanism_string_id(enum pkcs11_mechanism_id id);
#endif

uint32_t *tee_malloc_mechanism_list(size_t *out_count);

uint32_t mechanism_supported_flags(enum pkcs11_mechanism_id id);

void pkcs11_mechanism_supported_key_sizes(uint32_t proc_id,
					  uint32_t *min_key_size,
					  uint32_t *max_key_size);

void mechanism_supported_key_sizes_bytes(uint32_t proc_id,
					 uint32_t *min_key_size,
					 uint32_t *max_key_size);

static inline bool mechanism_is_supported(enum pkcs11_mechanism_id id)
{
	return mechanism_supported_flags(id) != 0;
}

#endif /*TOKEN_CAPABILITIES_H*/
