/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * GPCE hash driver definitions.
 */

#ifndef QCOM_GPCE_HASH_H
#define QCOM_GPCE_HASH_H

#include <stdbool.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <utee_defines.h>
#include <util.h>

#include "ce_hal.h"

#define SHA1_DIGEST_SIZE	U(20)
#define CE_MAX_BLOCK_SIZE	U(64)
#define CE_HW_BLOCK_SIZE	U(16)

#define SHA1_INITIAL_H0	UINT32_C(0x67452301)
#define SHA1_INITIAL_H1	UINT32_C(0xefcdab89)
#define SHA1_INITIAL_H2	UINT32_C(0x98badcfe)
#define SHA1_INITIAL_H3	UINT32_C(0x10325476)
#define SHA1_INITIAL_H4	UINT32_C(0xc3d2e1f0)

#define INIT_DATA_CE_SHA1_h0	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H0)
#define INIT_DATA_CE_SHA1_h1	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H1)
#define INIT_DATA_CE_SHA1_h2	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H2)
#define INIT_DATA_CE_SHA1_h3	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H3)
#define INIT_DATA_CE_SHA1_h4	TEE_U32_TO_BIG_ENDIAN(SHA1_INITIAL_H4)

/*
 * struct qce_dev_s - Shared Crypto Engine device state
 *
 * @mutex: Serializes access to the Crypto Engine
 * @base: Virtual base address of the Crypto Engine registers
 */
struct qce_dev_s {
	struct mutex mutex;
	vaddr_t base;
};

/*
 * struct ce_sha_ctx_s - SHA state maintained by the Crypto Engine
 *
 * @ce_ctx: Crypto Engine configuration and digest state
 * @block: Input data retained until a complete SHA block is available
 * @block_len: Number of valid bytes in @block
 * @first: True until the first input block is submitted
 */
struct ce_sha_ctx_s {
	struct ce_ctx *ce_ctx;
	uint8_t block[CE_MAX_BLOCK_SIZE];
	size_t block_len;
	bool first;
};

/*
 * struct qce_hash_state - Per-operation GPCE hash state
 *
 * @md_sz: Digest size in bytes
 * @flags: Operation flags
 * @dev: Shared Crypto Engine device state
 * @ctx: Algorithm-specific state
 * @ctx_sz: Size of @ctx in bytes
 */
struct qce_hash_state {
	size_t md_sz;
	uint32_t flags;
	struct qce_dev_s *dev;
	void *ctx;
	size_t ctx_sz;
};

#define HASH_GET_DIGEST_CTX(hash, type) ((type *)((hash)->ctx))
#define HASH_IS_CTX_NULL(ctx) (!(ctx))

/*
 * SHA_CMN_CE_init() - Initialize a hash context for a new operation
 * @me: Hash context with a valid device reference
 *
 * Allocates and initializes the driver-private hash state.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * TEE_ERROR_OUT_OF_MEMORY on allocation failure, or a hardware error.
 */
TEE_Result SHA_CMN_CE_init(struct qce_hash_state *me);

/*
 * SHA_CMN_CE_update() - Buffer or process hash input data
 * @me: Initialized hash context
 * @msg: Input buffer, or NULL when @msg_sz is zero
 * @msg_sz: Number of bytes in @msg
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS for an invalid
 * input buffer, TEE_ERROR_BAD_STATE for an invalid context, or a hardware
 * error.
 */
TEE_Result SHA_CMN_CE_update(struct qce_hash_state *me, const uint8_t *msg,
			     size_t msg_sz);

/*
 * SHA_CMN_CE_final() - Complete a hash operation and return its digest
 * @me: Initialized hash context
 * @md: Output digest buffer
 * @md_sz: Size of @md in bytes
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * TEE_ERROR_BAD_PARAMETERS for an invalid output buffer, or a hardware error.
 */
TEE_Result SHA_CMN_CE_final(struct qce_hash_state *me, uint8_t *md,
			    size_t md_sz);

/*
 * SHA_CMN_CE_reset() - Reset a hash context for another operation
 * @me: Hash context to reset
 *
 * Return: TEE_SUCCESS on success or a hardware error.
 */
TEE_Result SHA_CMN_CE_reset(struct qce_hash_state *me);

/*
 * SHA_CMN_CE_cleanup() - Release driver-private hash state
 * @me: Hash context to clean up
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * or a hardware error.
 */
TEE_Result SHA_CMN_CE_cleanup(struct qce_hash_state *me);

/*
 * SHA_CMN_CE_copy() - Copy one hash context into another
 * @dest: Initialized destination hash context
 * @src: Source hash context
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for invalid contexts,
 * TEE_ERROR_OUT_OF_MEMORY if the CE state cannot be allocated, or a hardware
 * error.
 */
TEE_Result SHA_CMN_CE_copy(struct qce_hash_state *dst,
			   struct qce_hash_state *src);

#endif /* QCOM_GPCE_HASH_H */
