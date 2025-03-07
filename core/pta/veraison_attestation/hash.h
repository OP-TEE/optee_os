/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#ifndef PTA_VERAISON_ATTESTATION_HASH_H
#define PTA_VERAISON_ATTESTATION_HASH_H

#include <stddef.h>
#include <stdint.h>
#include <tee_api.h>

TEE_Result get_hash_ta_memory(uint8_t out[TEE_SHA256_HASH_SIZE]);

#endif /* PTA_VERAISON_ATTESTATION_HASH_H */
