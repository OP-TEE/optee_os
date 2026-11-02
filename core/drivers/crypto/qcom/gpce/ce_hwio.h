/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
 *
 * Crypto Engine register access definitions.
 */

#ifndef QCOM_GPCE_CE_HWIO_H
#define QCOM_GPCE_CE_HWIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>

#include "hash.h"

/*
 * CE_HWIO_set_ce_ctx() - Program the Crypto Engine hash context
 * @ctx: Hash operation state
 * @auth_sz: Number of authenticated bytes processed before this segment
 * @seg_sz: Size of the input segment in bytes
 * @first: True for the first segment of an operation
 * @last: True for the final segment of an operation
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * or a hardware error.
 */
TEE_Result CE_HWIO_set_ce_ctx(struct qce_hash_state *ctx, size_t auth_sz,
			      size_t seg_sz, bool first, bool last);

/*
 * CE_HWIO_get_ce_ctx() - Read the Crypto Engine hash context
 * @ctx: Hash operation state that receives the updated context
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE for an invalid context,
 * TEE_ERROR_TIMEOUT if the operation does not complete, or a hardware error.
 */
TEE_Result CE_HWIO_get_ce_ctx(struct qce_hash_state *ctx);

/*
 * CE_HWIO_xfer_data() - Transfer input data to the Crypto Engine
 * @ctx: Hash operation state
 * @ibuf: Input buffer
 * @isz: Number of bytes to transfer
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_PARAMETERS for an invalid
 * buffer, TEE_ERROR_BAD_STATE for an invalid context, TEE_ERROR_TIMEOUT if
 * the CE FIFO does not become ready, or a hardware error.
 */
TEE_Result CE_HWIO_xfer_data(struct qce_hash_state *ctx, const uint8_t *ibuf,
			     size_t isz);

#endif /* QCOM_GPCE_CE_HWIO_H */
