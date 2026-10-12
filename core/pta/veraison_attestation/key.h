/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2026 RICSec
 */

#ifndef PTA_VERAISON_ATTESTATION_KEY_H
#define PTA_VERAISON_ATTESTATION_KEY_H

#include <stdint.h>
#include <tee_api_types.h>

#include "sign.h"

/*
 * The signing key of the PTA: the embedded test key with
 * CFG_VERAISON_ATTESTATION_PTA_TEST_KEY=y, otherwise a key the PTA keeps
 * in its private secure storage, generated on first use or installed
 * before that with key_import(). The key never leaves the PTA and is never
 * replaced once stored.
 */

/**
 * Get the signing key, generating and storing one on first use
 * @param skey      [out] The key, owned by the PTA
 * @return TEE_SUCCESS if successful
 */
TEE_Result key_get(const struct signing_key **skey);

/**
 * Store a signing key generated elsewhere, while the PTA has none
 * @param pub_x     Public key X coordinate, SIGNING_KEY_COORD_SIZE bytes
 * @param pub_y     Public key Y coordinate, SIGNING_KEY_COORD_SIZE bytes
 * @param priv      Plain private key, SIGNING_KEY_COORD_SIZE bytes
 * @param skey      [out] The stored key, owned by the PTA
 * @return TEE_SUCCESS if successful, TEE_ERROR_ACCESS_CONFLICT if the PTA
 *         already has a key, TEE_ERROR_BAD_PARAMETERS if the private key
 *         does not match the public key, TEE_ERROR_NOT_SUPPORTED with the
 *         test key
 */
TEE_Result key_import(const uint8_t *pub_x, const uint8_t *pub_y,
		      const uint8_t *priv, const struct signing_key **skey);

#endif /* PTA_VERAISON_ATTESTATION_KEY_H */
