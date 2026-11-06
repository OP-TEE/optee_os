/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc.
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

#define MAX_AUTH_BYTE_COUNT	U(4)
#define MAX_AUTH_IV_COUNT	U(16)

/*
 * struct ce_ctx - Crypto Engine hash context
 *
 * @flags: Crypto Engine configuration flags
 * @auth_iv: Authentication initialization vector and resulting digest words
 * @auth_byte_cnt: Authentication byte count maintained by the engine
 */
struct ce_ctx {
	uint32_t flags;
	uint32_t auth_iv[MAX_AUTH_IV_COUNT];
	uint32_t auth_byte_cnt[MAX_AUTH_BYTE_COUNT];
};

#define CE_HAL_SET_FLAGS(me, v) ((me)->flags |= (v))

static inline bool CE_HAL_IS_FLAG_SET(const struct ce_ctx *me, uint32_t flags)
{
	return (me->flags & flags) == flags;
}

/*
 * CE_HAL_new() - Allocate a Crypto Engine context
 *
 * Return: Allocated context on success or NULL on allocation failure.
 */
struct ce_ctx *CE_HAL_new(void);

/*
 * CE_HAL_free() - Clear and release a Crypto Engine context
 * @me: Context to release
 *
 * Return: TEE_SUCCESS on success or TEE_ERROR_BAD_STATE if @me is NULL.
 */
TEE_Result CE_HAL_free(struct ce_ctx *me);

/*
 * CE_HAL_reset() - Reset the authentication state in a CE context
 * @me: Context to reset
 *
 * Return: TEE_SUCCESS on success or TEE_ERROR_BAD_STATE if @me is NULL.
 */
TEE_Result CE_HAL_reset(struct ce_ctx *me);

/*
 * CE_HAL_init() - Initialize a Crypto Engine context for hashing
 * @me: Context to initialize
 * @little_endian: True to configure little-endian input data
 *
 * Return: TEE_SUCCESS on success or TEE_ERROR_BAD_STATE if @me is NULL.
 */
TEE_Result CE_HAL_init(struct ce_ctx *me, bool little_endian);

/*
 * CE_HAL_set_auth_iv() - Set an authentication IV word
 * @me: Crypto Engine context
 * @idx: IV word index
 * @iv: IV word value
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE if @me is NULL, or
 * TEE_ERROR_BAD_PARAMETERS if @idx is outside the IV array.
 */
TEE_Result CE_HAL_set_auth_iv(struct ce_ctx *me, uint8_t idx, uint32_t iv);

/*
 * CE_HAL_get_auth_iv() - Copy authentication IV words from a CE context
 * @me: Crypto Engine context
 * @buf: Output buffer
 * @sz: Size of @buf in bytes
 *
 * Return: TEE_SUCCESS on success, TEE_ERROR_BAD_STATE if @me is NULL, or
 * TEE_ERROR_BAD_PARAMETERS for an invalid or oversized output buffer.
 */
TEE_Result CE_HAL_get_auth_iv(struct ce_ctx *me, uint8_t *buf, size_t sz);

/*
 * CE_HAL_copy() - Copy one Crypto Engine context into another
 * @dest: Destination context
 * @src: Source context
 *
 * Return: TEE_SUCCESS on success or TEE_ERROR_BAD_STATE if either context is
 * NULL.
 */
TEE_Result CE_HAL_copy(struct ce_ctx *dest, struct ce_ctx *src);

#endif /* QCOM_GPCE_CE_HAL_H */
