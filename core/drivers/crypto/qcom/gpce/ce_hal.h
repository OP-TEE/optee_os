/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Qualcomm Technologies, Inc.
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
#define CE_HAL_FLAGS_IS_AUTH_ENG_EN	UINT32_C(0x00000100)

#define MAX_AUTH_BYTE_COUNT	U(4)
#define MAX_AUTH_IV_COUNT	U(16)

struct ce_ctx {
	uint32_t flags;
	uint32_t auth_iv[MAX_AUTH_IV_COUNT];
	uint32_t auth_byte_cnt[MAX_AUTH_BYTE_COUNT];
};

#define CE_HAL_SET_FLAGS(ctx, mask) ((ctx)->flags |= (mask))
#define CE_HAL_CLR_FLAGS(ctx, mask) ((ctx)->flags &= ~(mask))
static inline bool ce_hal_flag_set(const struct ce_ctx *ctx, uint32_t mask)
{
	return (ctx->flags & mask) == mask;
}

struct ce_ctx *CE_HAL_new(void);
TEE_Result CE_HAL_free(struct ce_ctx *me);
TEE_Result CE_HAL_reset(struct ce_ctx *me);
TEE_Result CE_HAL_init(struct ce_ctx *me, bool little_endian);
TEE_Result CE_HAL_set_auth_iv(struct ce_ctx *me, uint8_t idx, uint32_t iv);
TEE_Result CE_HAL_get_auth_iv(struct ce_ctx *me, uint8_t *buf, size_t sz);
TEE_Result CE_HAL_copy(struct ce_ctx *dest, struct ce_ctx *src);

#endif /* QCOM_GPCE_CE_HAL_H */
