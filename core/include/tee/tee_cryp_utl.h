/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#ifndef TEE_CRYP_UTL_H
#define TEE_CRYP_UTL_H

#include <tee_api_types.h>
#include <crypto/crypto.h>

TEE_Result tee_alg_get_digest_size(uint32_t algo, size_t *size);
TEE_Result tee_hash_createdigest(uint32_t algo, const uint8_t *data,
				 size_t datalen, uint8_t *digest,
				 size_t digestlen);
TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size);
TEE_Result tee_do_cipher_update(void *ctx, uint32_t algo,
				TEE_OperationMode mode, bool last_block,
				const uint8_t *data, size_t len, uint8_t *dst);

/*
 * plat_prng_add_jitter_entropy() - Adds jitter to RNG entropy pool
 * @sid:	source ID, normally unique per location of the call
 * @pnum:	pointer where the pool number for this @sid is stored
 *
 * Note that the supplied @sid controls (CRYPTO_RNG_SRC_IS_QUICK()) whether
 * RPC is allowed to be performed or the event just will be queued for later
 * consumption.
 */
void plat_prng_add_jitter_entropy(enum crypto_rng_src sid, unsigned int *pnum);

void plat_rng_init(void);

#endif
