// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2022 Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/huk_subkey.h>
#include <kernel/ldelf_loader.h>
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tpm.h>
#include <kernel/user_access.h>
#include <kernel/user_mode_ctx.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/vm.h>
#include <pta_system.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_defines.h>
#include <tee/tee_supp_plugin_rpc.h>
#include <util.h>

static unsigned int system_pnum;

static TEE_Result system_rng_reseed(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	size_t entropy_sz = 0;
	uint8_t *entropy_input = NULL;
	void *seed_bbuf = NULL;
	TEE_Result res = TEE_SUCCESS;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	entropy_input = params[0].memref.buffer;
	entropy_sz = params[0].memref.size;

	if (!entropy_sz || !entropy_input)
		return TEE_ERROR_BAD_PARAMETERS;

	res = bb_memdup_user(entropy_input, entropy_sz, &seed_bbuf);
	if (res)
		return res;

	crypto_rng_add_event(CRYPTO_RNG_SRC_NONSECURE, &system_pnum,
			     seed_bbuf, entropy_sz);

	bb_free(seed_bbuf, entropy_sz);

	return TEE_SUCCESS;
}

static TEE_Result system_derive_ta_unique_key(struct user_mode_ctx *uctx,
					      uint32_t param_types,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	size_t data_len = sizeof(TEE_UUID);
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t *data = NULL;
	uint32_t access_flags = 0;
	void *subkey_bbuf = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size > TA_DERIVED_EXTRA_DATA_MAX_SIZE ||
	    params[1].memref.size < TA_DERIVED_KEY_MIN_SIZE ||
	    params[1].memref.size > TA_DERIVED_KEY_MAX_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

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
	res = vm_check_access_rights(uctx, access_flags,
				     (uaddr_t)params[1].memref.buffer,
				     params[1].memref.size);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_SECURITY;

	/* Take extra data into account. */
	if (ADD_OVERFLOW(data_len, params[0].memref.size, &data_len))
		return TEE_ERROR_SECURITY;

	data = bb_alloc(data_len);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(data, &uctx->ts_ctx->uuid, sizeof(TEE_UUID));

	/* Append the user provided data */
	res = copy_from_user(data + sizeof(TEE_UUID), params[0].memref.buffer,
			     params[0].memref.size);
	if (res)
		goto out;

	subkey_bbuf = bb_alloc(params[1].memref.size);
	if (!subkey_bbuf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = huk_subkey_derive(HUK_SUBKEY_UNIQUE_TA, data, data_len,
				subkey_bbuf, params[1].memref.size);
	if (res)
		goto out;

	res = copy_to_user(params[1].memref.buffer, subkey_bbuf,
			   params[1].memref.size);

out:
	bb_free_wipe(subkey_bbuf, params[1].memref.size);
	bb_free_wipe(data, data_len);
	return res;
}

static TEE_Result system_map_zi(struct user_mode_ctx *uctx,
				uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE);
	uint32_t prot = TEE_MATTR_URW | TEE_MATTR_PRW;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct mobj *mobj = NULL;
	uint32_t pad_begin = 0;
	uint32_t vm_flags = 0;
	struct fobj *f = NULL;
	uint32_t pad_end = 0;
	size_t num_bytes = 0;
	vaddr_t va = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].value.b & ~PTA_SYSTEM_MAP_FLAG_SHAREABLE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.b & PTA_SYSTEM_MAP_FLAG_SHAREABLE)
		vm_flags |= VM_FLAG_SHAREABLE;

	num_bytes = params[0].value.a;
	va = reg_pair_to_64(params[1].value.a, params[1].value.b);
	pad_begin = params[2].value.a;
	pad_end = params[2].value.b;

	f = fobj_ta_mem_alloc(ROUNDUP_DIV(num_bytes, SMALL_PAGE_SIZE));
	if (!f)
		return TEE_ERROR_OUT_OF_MEMORY;
	mobj = mobj_with_fobj_alloc(f, NULL, TEE_MATTR_MEM_TYPE_TAGGED);
	fobj_put(f);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = vm_map_pad(uctx, &va, num_bytes, prot, vm_flags,
			 mobj, 0, pad_begin, pad_end, 0);
	mobj_put(mobj);
	if (!res)
		reg_pair_from_64(va, &params[1].value.a, &params[1].value.b);

	return res;
}

static TEE_Result system_unmap(struct user_mode_ctx *uctx, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_SUCCESS;
	uint32_t vm_flags = 0;
	vaddr_t end_va = 0;
	vaddr_t va = 0;
	size_t sz = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.b)
		return TEE_ERROR_BAD_PARAMETERS;

	va = reg_pair_to_64(params[1].value.a, params[1].value.b);
	sz = ROUNDUP(params[0].value.a, SMALL_PAGE_SIZE);

	/*
	 * The vm_get_flags() and vm_unmap() are supposed to detect or
	 * handle overflow directly or indirectly. However, this function
	 * an API function so an extra guard here is in order. If nothing
	 * else to make it easier to review the code.
	 */
	if (ADD_OVERFLOW(va, sz, &end_va))
		return TEE_ERROR_BAD_PARAMETERS;

	res = vm_get_flags(uctx, va, sz, &vm_flags);
	if (res)
		return res;
	if (vm_flags & VM_FLAG_PERMANENT)
		return TEE_ERROR_ACCESS_DENIED;

	return vm_unmap(uctx, va, sz);
}

static TEE_Result system_dlopen(struct user_mode_ctx *uctx,
				uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ts_session *s = NULL;
	TEE_UUID uuid = { };
	uint32_t flags = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size != sizeof(uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	res = copy_from_user(&uuid, params[0].memref.buffer, sizeof(uuid));
	if (res)
		return res;

	flags = params[1].value.a;

	s = ts_pop_current_session();
	res = ldelf_dlopen(uctx, &uuid, flags);
	ts_push_current_session(s);

	return res;
}

static TEE_Result system_dlsym(struct user_mode_ctx *uctx, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE);
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ts_session *s = NULL;
	char *sym = NULL;
	TEE_UUID uuid = { };
	size_t symlen = 0;
	vaddr_t va = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size != sizeof(uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	res = copy_from_user(&uuid, params[0].memref.buffer, sizeof(uuid));
	if (res)
		return res;

	if (!params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
	res = bb_strndup_user(params[1].memref.buffer, params[1].memref.size,
			      &sym, &symlen);
	if (res)
		return res;

	s = ts_pop_current_session();
	res = ldelf_dlsym(uctx, &uuid, sym, symlen, &va);
	ts_push_current_session(s);

	if (!res)
		reg_pair_from_64(va, &params[2].value.a, &params[2].value.b);

	return res;
}

static TEE_Result system_get_tpm_event_log(uint32_t param_types,
					   TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	size_t size = 0;
	TEE_Result res = TEE_SUCCESS;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	size = params[0].memref.size;
	res = tpm_get_event_log(params[0].memref.buffer, &size);
	params[0].memref.size = size;

	return res;
}

static TEE_Result system_supp_plugin_invoke(uint32_t param_types,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INOUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT);
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t outlen = 0;
	TEE_UUID uuid = { };

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer || params[0].memref.size != sizeof(uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	res = copy_from_user(&uuid, params[0].memref.buffer, sizeof(uuid));
	if (res)
		return res;

	res = tee_invoke_supp_plugin_rpc(&uuid,
					 params[1].value.a, /* cmd */
					 params[1].value.b, /* sub_cmd */
					 NULL,
					 params[2].memref.buffer, /* data */
					 params[2].memref.size, /* in len */
					 &outlen);
	params[3].value.a = (uint32_t)outlen;

	return res;
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx __unused)
{
	struct ts_session *s = NULL;

	/* Check that we're called from a user TA */
	s = ts_get_calling_session();
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
	struct ts_session *s = ts_get_calling_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(s->ctx);

	switch (cmd_id) {
	case PTA_SYSTEM_ADD_RNG_ENTROPY:
		return system_rng_reseed(param_types, params);
	case PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY:
		return system_derive_ta_unique_key(uctx, param_types, params);
	case PTA_SYSTEM_MAP_ZI:
		return system_map_zi(uctx, param_types, params);
	case PTA_SYSTEM_UNMAP:
		return system_unmap(uctx, param_types, params);
	case PTA_SYSTEM_DLOPEN:
		return system_dlopen(uctx, param_types, params);
	case PTA_SYSTEM_DLSYM:
		return system_dlsym(uctx, param_types, params);
	case PTA_SYSTEM_GET_TPM_EVENT_LOG:
		return system_get_tpm_event_log(param_types, params);
	case PTA_SYSTEM_SUPP_PLUGIN_INVOKE:
		return system_supp_plugin_invoke(param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SYSTEM_UUID, .name = "system.pta",
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
