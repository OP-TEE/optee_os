/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#ifndef TOKEN_CAPABILITIES_H
#define TOKEN_CAPABILITIES_H

bool mechanism_flags_complies_pkcs11(uint32_t mechanism_type, uint32_t flags);

bool mechanism_is_valid(enum pkcs11_mechanism_id id);

#if CFG_TEE_TA_LOG_LEVEL > 0
const char *mechanism_string_id(enum pkcs11_mechanism_id id);
#endif

uint32_t *tee_malloc_mechanism_list(size_t *out_count);

uint32_t mechanism_supported_flags(enum pkcs11_mechanism_id id);

static inline bool mechanism_is_supported(enum pkcs11_mechanism_id id)
{
	return mechanism_supported_flags(id) != 0;
}

#endif /*TOKEN_CAPABILITIES_H*/
