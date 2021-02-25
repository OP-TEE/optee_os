// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021, Foundries Limited
 */

#include <crypto/crypto.h>
#include <io.h>
#include <kernel/delay.h>
#include <kernel/pseudo_ta.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <mm/core_memprot.h>
#include <rng_pta.h>
#include <string.h>

#define PTA_NAME "rng.pta"

static TEE_Result rng_get_entropy(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *e = NULL;
	uint32_t rq_size = 0;
	uint32_t exceptions;
	TEE_Result res = TEE_SUCCESS;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	rq_size = params[0].memref.size;
	e = (uint8_t *)params[0].memref.buffer;
	if (!e)
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	res = crypto_rng_read(e, rq_size);
	thread_set_exceptions(exceptions);

	return res;
}

static TEE_Result rng_get_info(uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	enum crypto_rng_quality quality = CRYPTO_RNG_IS_SW;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	crypto_rng_get_info(&quality);

	/*
	 * value.a is data rate: calls to crypto_rng_read will always generate
	 * the requested number of bytes from the crypto RNG framework. As a
	 * consequence, there is no need to artificially wait for it to generate
	 * additional data.
	 */
	params[0].value.a = UINT32_MAX;

	/* value.b is quality: 0 (unknown), 1 (lowest) and 1024(highest) */
	params[0].value.b = quality;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t cmd, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("pseudo-TA entry\"%s\"", PTA_NAME);

	switch (cmd) {
	case PTA_CMD_GET_ENTROPY:
		return rng_get_entropy(nParamTypes, pParams);
	case PTA_CMD_GET_RNG_INFO:
		return rng_get_info(nParamTypes, pParams);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

pseudo_ta_register(.uuid = PTA_RNG_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS |
			    TA_FLAG_DEVICE_ENUM | TA_FLAG_CONCURRENT,
		   .invoke_command_entry_point = invoke_command);
