// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Implementation of Crypto Engine hash context helpers.
 */

#include "ce_hal.h"
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>

#include <tee_api_types.h>
#include <tee_api_defines.h>

struct qce_ce_ctx *ce_hal_new(void)
{
	struct qce_ce_ctx *ctx = calloc(1, sizeof(*ctx));

	return ctx;
}

TEE_Result ce_hal_free(struct qce_ce_ctx *me)
{
	if (!me)
		return TEE_ERROR_BAD_STATE;
	memzero_explicit(me, sizeof(*me));
	free(me);

	return TEE_SUCCESS;
}

TEE_Result ce_hal_init(struct qce_ce_ctx *me, bool little_endian)
{
	if (!me)
		return TEE_ERROR_BAD_STATE;

	if (little_endian)
		CE_HAL_SET_FLAGS(me, CE_HAL_FLAGS_IS_LITTLE_ENDIAN);
	CE_HAL_SET_FLAGS(me, CE_HAL_FLAGS_IS_AUTH_ENG_EN);

	return TEE_SUCCESS;
}

TEE_Result ce_hal_set_auth_iv(struct qce_ce_ctx *me, uint8_t idx, uint32_t iv)
{
	if (!me)
		return TEE_ERROR_BAD_STATE;
	if (idx >= ARRAY_SIZE(me->auth_iv))
		return TEE_ERROR_BAD_PARAMETERS;
	me->auth_iv[idx] = iv;

	return TEE_SUCCESS;
}

TEE_Result ce_hal_get_auth_iv(struct qce_ce_ctx *me, uint8_t *buf, size_t sz)
{
	if (!me)
		return TEE_ERROR_BAD_STATE;
	if (!buf || sz > sizeof(me->auth_iv))
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(buf, me->auth_iv, sz);

	return TEE_SUCCESS;
}

TEE_Result ce_hal_copy(struct qce_ce_ctx *dest, struct qce_ce_ctx *src)
{
	if (!src)
		return TEE_ERROR_BAD_STATE;
	if (!dest)
		return TEE_ERROR_BAD_STATE;
	memcpy(dest, src, sizeof(*dest));

	return TEE_SUCCESS;
}
