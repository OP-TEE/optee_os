// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, Linaro Limited
 * Copyright (c) 2021, EPAM Systems. All rights reserved.
 *
 * Based on plat-synquacer/rng_pta.c
 *
 */

#include <assert.h>
#include <config.h>
#include <crypto/crypto.h>
#include <kernel/pseudo_ta.h>
#include <pta_rng.h>
#include <rng_support.h>

#define PTA_NAME "rng.pta"

/* This PTA only works with hardware random number generators */
static_assert(!IS_ENABLED(CFG_WITH_SOFTWARE_PRNG));

static TEE_Result rng_get_entropy(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *e = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		DMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	e = (uint8_t *)params[0].memref.buffer;
	if (!e)
		return TEE_ERROR_BAD_PARAMETERS;

	return crypto_rng_read(e, params[0].memref.size);
}

static TEE_Result rng_get_info(uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		DMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	params[0].value.a = CFG_HWRNG_RATE;
	params[0].value.b = CFG_HWRNG_QUALITY;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_GET_ENTROPY:
		return rng_get_entropy(ptypes, params);
	case PTA_CMD_GET_RNG_INFO:
		return rng_get_info(ptypes, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_RNG_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT |
			    TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
