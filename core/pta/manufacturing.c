// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Pengutronix e.K.
 */

#include <kernel/pseudo_ta.h>
#include <tee/tee_fs.h>
#include <pta_manufacturing.h>
#include <crypto/crypto.h>

static void rand_delay(void)
{
	volatile int loops = 0;

	crypto_rng_read(&loops, sizeof(loops));
	loops &= 0x3FF; /* cap to 10 bits */

	while (--loops >= 0) {
		loops++;
		loops--;
	}
}

TEE_Result __weak
pta_manufacturing_query_state(enum pta_manufacturing_state *state)
{
	*state = PTA_MANUFACTURING_STATE_UNKNOWN;
	return TEE_SUCCESS;
}

TEE_Result __weak
pta_manufacturing_set_state(enum pta_manufacturing_state state __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result manufacturing_get_state(uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types) {
		DMSG("Wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return pta_manufacturing_query_state(&params[0].value.a);
}

static TEE_Result manufacturing_set_state(uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	enum pta_manufacturing_state next = PTA_MANUFACTURING_STATE_UNKNOWN;
	enum pta_manufacturing_state current = PTA_MANUFACTURING_STATE_LOCKED;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (exp_pt != param_types) {
		DMSG("Wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	next = (enum pta_manufacturing_state)params[0].value.a;
	res = pta_manufacturing_query_state(&current);
	if (res)
		return res;

	/* make glitching harder by adding a random delay. */
	rand_delay();

	if (next < current)
		return TEE_ERROR_SECURITY;

	if (next == current)
		return TEE_SUCCESS;

	return pta_manufacturing_set_state(next);
}

static TEE_Result manufacturing_get_rpmb_key(uint32_t param_types,
					     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	enum pta_manufacturing_state current = PTA_MANUFACTURING_STATE_LOCKED;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (exp_pt != param_types) {
		DMSG("Wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (params[0].memref.size != RPMB_EMMC_CID_SIZE) {
		DMSG("Wrong buffer size %d != %d", params[0].memref.size,
		     RPMB_EMMC_CID_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = pta_manufacturing_query_state(&current);
	if (res)
		return res;

	/* make glitching harder by adding a random delay. */
	rand_delay();

	if (current > PTA_MANUFACTURING_STATE_UNLOCKED)
		return TEE_ERROR_ACCESS_DENIED;

	if (!plat_rpmb_key_is_ready()) {
		DMSG("platform indicates RPMB key is not ready");
		return TEE_ERROR_BAD_STATE;
	}

	return tee_rpmb_key_gen(params[0].memref.buffer,
				params[1].memref.buffer, params[1].memref.size);
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_MANUFACTURING_QUERY_STATE:
		return manufacturing_get_state(param_types, params);
	case PTA_MANUFACTURING_SET_STATE:
		return manufacturing_set_state(param_types, params);
	case PTA_MANUFACTURING_GET_RPMB_KEY:
		return manufacturing_get_rpmb_key(param_types, params);
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_MANUFACTURING_UUID, .name = "manufacturing",
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
