/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <tee_api_types.h>

/*
 * Dummy functions makred as __weak,
 * some hardware specific hooks needed.
 */
TEE_Result attestation_get_sys_measurement(uint8_t *ptr);
TEE_Result attestation_get_endorsement_key(uint8_t *key);
TEE_Result attestation_decrypt_priv_key(uint8_t *plain, size_t *plain_size);

#endif
