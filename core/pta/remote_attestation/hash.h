// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Institute of Information Security (IISEC)
 */

#ifndef PTA_REMOTE_ATTESTATION_HASH_H
#define PTA_REMOTE_ATTESTATION_HASH_H

#include <stddef.h>
#include <stdint.h>

TEE_Result get_hash_ta_memory(uint8_t out[TEE_SHA256_HASH_SIZE]);

#endif /* PTA_REMOTE_ATTESTATION_HASH_H */
