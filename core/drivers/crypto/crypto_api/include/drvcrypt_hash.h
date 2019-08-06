/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Hash interface calling the HW crypto driver.
 */
#ifndef __DRVCRYPT_HASH_H__
#define __DRVCRYPT_HASH_H__

#include <tee_api_types.h>

/*
 * Crypto Library Hash driver operations
 */
struct drvcrypt_hash {
	/* Allocates of the Software context */
	TEE_Result (*alloc_ctx)(void **ctx, uint8_t hash_id);
	/* Free of the Software context */
	void (*free_ctx)(void *ctx);
	/* Initialize the hashing operation */
	TEE_Result (*init)(void *ctx);
	/* Update the hashing operation */
	TEE_Result (*update)(void *ctx, const uint8_t *data, size_t len);
	/* Finalize the hashing operation */
	TEE_Result (*final)(void *ctx, uint8_t *digest, size_t len);
	/* Copy Hash context */
	void (*copy_state)(void *dst_ctx, void *src_ctx);
};

#endif /* __DRVCRYPT_HASH_H__ */
