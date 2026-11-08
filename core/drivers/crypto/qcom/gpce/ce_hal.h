/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Crypto Engine hash context definitions.
 */
#ifndef QCOM_GPCE_CE_HAL_H
#define QCOM_GPCE_CE_HAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <tee_api_defines.h>
#include <util.h>

#define CE_HAL_FLAGS_IS_LITTLE_ENDIAN	UINT32_C(0x00000004)
#define CE_HAL_FLAGS_IS_AUTH_ENG_EN	    UINT32_C(0x00000100)

#define QCE_MAX_AUTH_BYTE_COUNT	U(4)
#define QCE_MAX_AUTH_IV_COUNT	U(16)

/*
 * struct qce_ce_ctx - Crypto Engine hash context
 *
 * @flags: Crypto Engine configuration flags
 * @auth_iv: Authentication initialization vector and resulting digest words
 * @auth_byte_cnt: Authentication byte count maintained by the engine
 */
struct qce_ce_ctx {
	uint32_t flags;
	uint32_t auth_iv[QCE_MAX_AUTH_IV_COUNT];
	uint32_t auth_byte_cnt[QCE_MAX_AUTH_BYTE_COUNT];
};

#define CE_HAL_SET_FLAGS(me, v) ((me)->flags |= (v))
#define CE_HAL_IS_FLAG_SET(me, flag) (!!((me)->flags & (flag)))

/*
 * ce_hal_new() - Allocate a Crypto Engine context
 *
 * Return: Allocated context on success or NULL on allocation failure.
 */
struct qce_ce_ctx *ce_hal_new(void);

/*
 * ce_hal_free() - Clear and release a Crypto Engine context
 * @me: Context to release
 *
 * Return: TEE_SUCCESS on success or TEE_ERROR_BAD_STATE if @me is NULL.
 */
TEE_Result ce_hal_free(struct qce_ce_ctx *me);

/*
 * ce_hal_init() - Initialize a Crypto Engine context for hashing
 * @me: Context to initialize
 * @little_endian: True to configure little-endian input data
 *
 * Return: TEE_SUCCESS on success or TEE_ERROR_BAD_STATE if @me is NULL.
 */
TEE_Result ce_hal_init(struct qce_ce_ctx *me, bool little_endian);

/*
 * ce_hal_set_auth_iv() - Set an authentication IV word
 * @me: Crypto Engine context
 * @idx: IV word index
 * @iv: IV word value
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE if @me is NULL, or
 * TEE_ERROR_BAD_PARAMETERS if @idx is outside the IV array.
 */
TEE_Result ce_hal_set_auth_iv(struct qce_ce_ctx *me, uint8_t idx, uint32_t iv);

/*
 * ce_hal_get_auth_iv() - Copy authentication IV words from a CE context
 * @me: Crypto Engine context
 * @buf: Output buffer
 * @sz: Size of @buf in bytes
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE if @me is NULL, or
 * TEE_ERROR_BAD_PARAMETERS for an invalid or oversized output buffer.
 */
TEE_Result ce_hal_get_auth_iv(struct qce_ce_ctx *me, uint8_t *buf, size_t sz);

/*
 * ce_hal_copy() - Copy one Crypto Engine context into another
 * @dest: Destination context
 * @src: Source context
 *
 * Return: TEE_SUCCESS on success or TEE_ERROR_BAD_STATE if either context is
 * NULL.
 */
TEE_Result ce_hal_copy(struct qce_ce_ctx *dest, struct qce_ce_ctx *src);

#endif /* QCOM_GPCE_CE_HAL_H */
