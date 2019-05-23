// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <crypto/crypto.h>
#include <kernel/huk_subkey.h>
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu.h>
#include <pta_system.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_defines.h>
#include <util.h>

#define MAX_ENTROPY_IN			32u

static unsigned int system_pnum;

static TEE_Result system_rng_reseed(struct tee_ta_session *s __unused,
				uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	size_t entropy_sz;
	uint8_t *entropy_input;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	entropy_input = params[0].memref.buffer;
	entropy_sz = params[0].memref.size;

	/* Fortuna PRNG requires seed <= 32 bytes */
	if (!entropy_sz)
		return TEE_ERROR_BAD_PARAMETERS;

	entropy_sz = MIN(entropy_sz, MAX_ENTROPY_IN);

	crypto_rng_add_event(CRYPTO_RNG_SRC_NONSECURE, &system_pnum,
			     entropy_input, entropy_sz);
	return TEE_SUCCESS;
}

static TEE_Result system_derive_ta_unique_key(struct tee_ta_session *s,
					      uint32_t param_types,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	size_t data_len = sizeof(TEE_UUID);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *data = NULL;
	uint32_t access_flags = 0;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct user_ta_ctx *utc = NULL;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > TA_DERIVED_EXTRA_DATA_MAX_SIZE ||
	    params[1].memref.size < TA_DERIVED_KEY_MIN_SIZE ||
	    params[1].memref.size > TA_DERIVED_KEY_MAX_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	utc = to_user_ta_ctx(s->ctx);

	/*
	 * The derived key shall not end up in non-secure memory by
	 * mistake.
	 *
	 * Note that we're allowing shared memory as long as it's
	 * secure. This is needed because a TA always uses shared memory
	 * when communicating with another TA.
	 */
	access_flags = TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER |
		       TEE_MEMORY_ACCESS_SECURE;
	res = tee_mmu_check_access_rights(utc, access_flags,
					  (uaddr_t)params[1].memref.buffer,
					  params[1].memref.size);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_SECURITY;

	/* Take extra data into account. */
	if (ADD_OVERFLOW(data_len, params[0].memref.size, &data_len))
		return TEE_ERROR_SECURITY;

	data = calloc(data_len, 1);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(data, &s->ctx->uuid, sizeof(TEE_UUID));

	/* Append the user provided data */
	memcpy(data + sizeof(TEE_UUID), params[0].memref.buffer,
	       params[0].memref.size);

	res = huk_subkey_derive(HUK_SUBKEY_UNIQUE_TA, data, data_len,
				params[1].memref.buffer,
				params[1].memref.size);
	free(data);

	return res;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct tee_ta_session *s;

	/* Check that we're called from a user TA */
	s = tee_ta_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	if (!is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	struct tee_ta_session *s = tee_ta_get_calling_session();

	switch (cmd_id) {
	case PTA_SYSTEM_ADD_RNG_ENTROPY:
		return system_rng_reseed(s, param_types, params);

	case PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY:
		return system_derive_ta_unique_key(s, param_types, params);

	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SYSTEM_UUID, .name = "system.pta",
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
