// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Broadcom
 */

#include <drivers/bcm_hwrng.h>
#include <io.h>
#include <kernel/pseudo_ta.h>
#include <trace.h>

#define HWRNG_SERVICE_UUID \
		{ 0x6272636D, 0x2019, 0x0201,  \
		{ 0x42, 0x43, 0x4D, 0x5F, 0x52, 0x4E, 0x47, 0x30 } }

/*
 * Get a HW generated random number
 *
 * [out]     value[0].a: Generated 32-bit random number
 */
#define PTA_BCM_HWRNG_CMD_GET	0

#define HWRNG_TA_NAME		"pta_hwrng.ta"

static TEE_Result pta_hwrng_get(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t num_words = 0;
	uint32_t rnd_num = 0;
	uint32_t res = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	num_words = bcm_hwrng_read_rng(&rnd_num, 1);

	if (num_words < 1) {
		res = TEE_ERROR_NO_DATA;
	} else {
		DMSG("Random Value is: 0x%08x", rnd_num);
		params[0].value.a = rnd_num;
		res = TEE_SUCCESS;
	}

	return res;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, HWRNG_TA_NAME);

	switch (cmd_id) {
	case PTA_BCM_HWRNG_CMD_GET:
		res = pta_hwrng_get(param_types, params);
		break;
	default:
		EMSG("cmd: %d Not supported %s", cmd_id, HWRNG_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = HWRNG_SERVICE_UUID,
		   .name = HWRNG_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
