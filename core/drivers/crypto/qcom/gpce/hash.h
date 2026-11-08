/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
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

#define QCE_SHA_BLOCK_SIZE	U(64)
#define QCE_HW_BLOCK_SIZE	U(16)

/*
 * struct qce_dev - Shared Crypto Engine device state
 *
 * @mutex: Serializes access to the Crypto Engine
 * @base: Virtual base address of the Crypto Engine registers
 */
struct qce_dev {
	struct mutex mutex;
	vaddr_t base;
};

/*
 * struct ce_sha_ctx - SHA state maintained by the Crypto Engine
 *
 * @ce_ctx: Crypto Engine configuration and digest state
 * @block: Input data retained until a complete SHA block is available
 * @block_len: Number of valid bytes in @block
 * @first: True until the first input block is submitted
 */
struct ce_sha_ctx {
	struct qce_ce_ctx *ce_ctx;
	uint8_t block[QCE_SHA_BLOCK_SIZE];
	size_t block_len;
	bool first;
};

/*
 * struct qce_hash_state - Per-operation GPCE hash state
 *
 * @dev: Shared Crypto Engine device state
 * @ctx: Algorithm-specific state
 * @ctx_sz: Size of @ctx in bytes
 */
struct qce_hash_state {
	struct qce_dev *dev;
	void *ctx;
	size_t ctx_sz;
};

#define HASH_GET_DIGEST_CTX(hash, type) ((type *)((hash)->ctx))
#define HASH_IS_CTX_NULL(ctx) (!(ctx))

static inline TEE_Result
qce_hash_get_sha_ctx(struct qce_hash_state *state,
		     struct ce_sha_ctx **sha_ctx)
{
	if (!state || !state->dev || !state->ctx || !sha_ctx ||
	    state->ctx_sz != sizeof(struct ce_sha_ctx))
		return TEE_ERROR_BAD_STATE;

	*sha_ctx = HASH_GET_DIGEST_CTX(state, struct ce_sha_ctx);
	return TEE_SUCCESS;
}

/*
 * sha_cmn_ce_init() - Initialize a hash context for a new operation
 * @me: Hash context with a valid device reference
 *
 * Allocates and initializes the driver-private hash state.
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * TEE_ERROR_OUT_OF_MEMORY on allocation failure, or a hardware error.
 */
TEE_Result sha_cmn_ce_init(struct qce_hash_state *me);

/*
 * sha_cmn_ce_update() - Buffer or process hash input data
 * @me: Initialized hash context
 * @msg: Input buffer, or NULL when @msg_sz is zero
 * @msg_sz: Number of bytes in @msg
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS for an invalid
 * input buffer, TEE_ERROR_BAD_STATE for an invalid context, or a hardware
 * error.
 */
TEE_Result sha_cmn_ce_update(struct qce_hash_state *me, const uint8_t *msg,
			     size_t msg_sz);

/*
 * sha_cmn_ce_final() - Complete a hash operation and return its digest
 * @me: Initialized hash context
 * @md: Output digest buffer
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * TEE_ERROR_BAD_PARAMETERS for an invalid output buffer, or a hardware error.
 */
TEE_Result sha_cmn_ce_final(struct qce_hash_state *me, uint8_t *md);

/*
 * sha_cmn_ce_cleanup() - Release driver-private hash state
 * @me: Hash context to clean up
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * or a hardware error.
 */
TEE_Result sha_cmn_ce_cleanup(struct qce_hash_state *me);

/*
 * sha_cmn_ce_copy() - Copy one hash context into another
 * @dest: Initialized destination hash context
 * @src: Source hash context
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for invalid contexts,
 * TEE_ERROR_OUT_OF_MEMORY if the CE state cannot be allocated, or a hardware
 * error.
 */
TEE_Result sha_cmn_ce_copy(struct qce_hash_state *dst,
			   struct qce_hash_state *src);

#endif /* QCOM_GPCE_HASH_H */
