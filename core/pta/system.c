// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/handle.h>
#include <kernel/huk_subkey.h>
#include <kernel/ldelf_loader.h>
#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tpm.h>
#include <kernel/ts_store.h>
#include <kernel/user_mode_ctx.h>
#include <ldelf.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/vm.h>
#include <optee_rpc_cmd.h>
#include <pta_system.h>
#include <stdlib_ext.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_defines.h>
#include <tee/tee_supp_plugin_rpc.h>
#include <tee/uuid.h>
#include <util.h>

#define PTR_ADD(ptr, offs) ((void *)((uintptr_t)(ptr) + (uintptr_t)(offs)))

#define ACCESS_RIGHTS_READ \
	(TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_ANY_OWNER)
#define ACCESS_RIGHTS_WRITE \
	(TEE_MEMORY_ACCESS_WRITE | TEE_MEMORY_ACCESS_ANY_OWNER)
#define ACCESS_RIGHTS_READ_WRITE (ACCESS_RIGHTS_READ | ACCESS_RIGHTS_WRITE)

struct bin_handle {
	const struct user_ta_store_ops *op;
	struct user_ta_store_handle *h;
	struct file *f;
	size_t offs_bytes;
	size_t size_bytes;
};

struct system_ctx {
	struct handle_db db;
	const struct user_ta_store_ops *store_op;
};

static unsigned int system_pnum;

static TEE_Result system_rng_reseed(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	size_t entropy_sz = 0;
	uint8_t *entropy_input = NULL;
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

	crypto_rng_add_event(CRYPTO_RNG_SRC_NONSECURE, &system_pnum,
			     entropy_input, entropy_sz);
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

	data = calloc(data_len, 1);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(data, &uctx->ts_ctx->uuid, sizeof(TEE_UUID));

	/* Append the user provided data */
	memcpy(data + sizeof(TEE_UUID), params[0].memref.buffer,
	       params[0].memref.size);

	res = huk_subkey_derive(HUK_SUBKEY_UNIQUE_TA, data, data_len,
				params[1].memref.buffer,
				params[1].memref.size);
	free_wipe(data);

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
	mobj = mobj_with_fobj_alloc(f, NULL);
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
	TEE_UUID *uuid = NULL;
	uint32_t flags = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uuid = params[0].memref.buffer;
	if (!uuid || params[0].memref.size != sizeof(*uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	flags = params[1].value.a;

	s = ts_pop_current_session();
	res = ldelf_dlopen(uctx, uuid, flags);
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
	const char *sym = NULL;
	TEE_UUID *uuid = NULL;
	size_t maxlen = 0;
	vaddr_t va = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uuid = params[0].memref.buffer;
	if (!uuid || params[0].memref.size != sizeof(*uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	sym = params[1].memref.buffer;
	if (!sym)
		return TEE_ERROR_BAD_PARAMETERS;
	maxlen = params[1].memref.size;

	s = ts_pop_current_session();
	res = ldelf_dlsym(uctx, uuid, sym, maxlen, &va);
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

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_invoke_supp_plugin_rpc(params[0].memref.buffer, /* uuid */
					 params[1].value.a, /* cmd */
					 params[1].value.b, /* sub_cmd */
					 params[2].memref.buffer, /* data */
					 params[2].memref.size, /* in len */
					 &outlen);
	params[3].value.a = (uint32_t)outlen;

	return res;
}

#ifdef CFG_USER_OCALL
static TEE_Result
ocall_check_memref_access_rights(const struct user_mode_ctx *uctx, uint32_t pt,
				 uaddr_t buffer, size_t size)
{
	uint32_t flags = 0;

	switch (pt) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
		flags = ACCESS_RIGHTS_READ;
		break;
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		flags = ACCESS_RIGHTS_READ_WRITE;
		break;
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		flags = ACCESS_RIGHTS_WRITE;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return vm_check_access_rights(uctx, flags, buffer, size);
}

static TEE_Result ocall_check_parameters(const struct user_mode_ctx *uctx,
					 const struct utee_params *up)
{
	TEE_Result res = TEE_SUCCESS;
	uaddr_t buffer = 0;
	size_t size = 0;
	uint32_t pt = 0;
	size_t n = 0;

	res = vm_check_access_rights(uctx, ACCESS_RIGHTS_READ_WRITE,
				     (uaddr_t)up, sizeof(*up));
	if (res)
		return res;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		pt = TEE_PARAM_TYPE_GET(up->types, n);
		switch (pt) {
		case TEE_PARAM_TYPE_NONE:
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			buffer = (uaddr_t)up->vals[n * 2];
			size = up->vals[n * 2 + 1];
			if ((buffer && !size) || (!buffer && size))
				return TEE_ERROR_BAD_PARAMETERS;
			res = ocall_check_memref_access_rights(uctx, pt, buffer,
							       size);
			if (res)
				return res;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	return res;
}

static TEE_Result ocall_compute_mobj_size(struct utee_params *up,
					  size_t *mobj_size)
{
	size_t total = 0;
	size_t size = 0;
	size_t n = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(up->types, n)) {
		case TEE_PARAM_TYPE_NONE:
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			size = up->vals[n * 2 + 1];
			if (ADD_OVERFLOW(total, size, &total))
				return TEE_ERROR_SECURITY;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	*mobj_size = total;

	return TEE_SUCCESS;
}

static TEE_Result ocall_pre_process(struct thread_param *params,
				    struct utee_params *up,
				    struct mobj *mobj,
				    void *mobj_va)
{
	uint32_t pt = 0;
	void *buffer = NULL;
	size_t size = 0;
	void *destination = NULL;
	size_t mobj_offs = 0;
	size_t n = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		pt = TEE_PARAM_TYPE_GET(up->types, n);
		switch (pt) {
		case TEE_PARAM_TYPE_NONE:
			params[n].attr = THREAD_PARAM_ATTR_NONE;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params[n].u.value.a = up->vals[n * 2];
			params[n].u.value.b = up->vals[n * 2 + 1];
			fallthrough;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
			params[n].attr = THREAD_PARAM_ATTR_VALUE_IN + pt -
					 TEE_PARAM_TYPE_VALUE_INPUT;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			buffer = (void *)(uintptr_t)up->vals[n * 2];
			size = up->vals[n * 2 + 1];
			if (buffer && pt != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
				destination = PTR_ADD(mobj_va, mobj_offs);
				memcpy(destination, buffer, size);
			}
			params[n].u.memref.mobj = mobj;
			params[n].u.memref.offs = mobj_offs;
			params[n].u.memref.size = size;
			params[n].attr = THREAD_PARAM_ATTR_MEMREF_IN + pt -
					 TEE_PARAM_TYPE_MEMREF_INPUT;
			if (ADD_OVERFLOW(mobj_offs, size, &mobj_offs))
				return TEE_ERROR_SECURITY;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result ocall_post_process(struct thread_param *params,
				     struct utee_params *up,
				     void *mobj_va)
{
	uint32_t pt = 0;
	void *buffer = NULL;
	size_t size = 0;
	void *source = NULL;
	size_t mobj_offs = 0;
	size_t n = 0;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		pt = TEE_PARAM_TYPE_GET(up->types, n);
		switch (pt) {
		case TEE_PARAM_TYPE_NONE:
		case TEE_PARAM_TYPE_VALUE_INPUT:
			break;
		case TEE_PARAM_TYPE_VALUE_INOUT:
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
			up->vals[n * 2] = params[n].u.value.a;
			up->vals[n * 2 + 1] = params[n].u.value.b;
			break;
		case TEE_PARAM_TYPE_MEMREF_INPUT:
			size = up->vals[n * 2 + 1];
			if (params[n].u.memref.size != size)
				return TEE_ERROR_BAD_PARAMETERS;
			if (ADD_OVERFLOW(mobj_offs, size, &mobj_offs))
				return TEE_ERROR_SECURITY;
			break;
		case TEE_PARAM_TYPE_MEMREF_INOUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
			buffer = (void *)(uintptr_t)up->vals[n * 2];
			size = up->vals[n * 2 + 1];
			if (params[n].u.memref.size > size)
				return TEE_ERROR_BAD_PARAMETERS;
			if (buffer) {
				source = PTR_ADD(mobj_va, mobj_offs);
				memcpy(buffer, source, params[n].u.memref.size);
				if (ADD_OVERFLOW(mobj_offs, size, &mobj_offs))
					return TEE_ERROR_SECURITY;
			}
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result system_ocall(struct ts_session *cs, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	const struct user_ta_ctx *utc = to_user_ta_ctx(cs->ctx);
	struct thread_param rpc_params[THREAD_RPC_MAX_NUM_PARAMS] = { };
	const size_t rpc_num_params = ARRAY_SIZE(rpc_params);
	uint32_t ocall_id = 0;
	struct utee_params *ocall_up = NULL;
	size_t ocall_up_size = 0;
	struct mobj *mobj = NULL;
	size_t mobj_size = 0;
	void *mobj_va = NULL;
	TEE_Result res = TEE_SUCCESS;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ocall_up_size = params[1].memref.size;
	if (ocall_up_size != sizeof(*ocall_up))
		return TEE_ERROR_BAD_PARAMETERS;

	ocall_id = params[0].value.a;
	ocall_up = (struct utee_params *)params[1].memref.buffer; /* User ptr */

	res = ocall_check_parameters(&utc->uctx, ocall_up);
	if (res)
		return res;

	res = ocall_compute_mobj_size(ocall_up, &mobj_size);
	if (res)
		return res;

	if (mobj_size) {
		mobj = thread_rpc_alloc_client_app_payload(mobj_size);
		if (!mobj)
			return TEE_ERROR_OUT_OF_MEMORY;

		mobj_va = mobj_get_va(mobj, 0);
		if (!mobj_va) {
			res = TEE_ERROR_GENERIC;
			goto exit;
		}
	}

	rpc_params[0] = THREAD_PARAM_VALUE(INOUT, ocall_id, 0, 0);
	rpc_params[1] = THREAD_PARAM_VALUE(IN, 0, 0, 0);
	tee_uuid_to_octets((uint8_t *)&rpc_params[1].u.value,
			   &cs->ctx->uuid);

	res = ocall_pre_process(rpc_params + 2, ocall_up, mobj, mobj_va);
	if (res)
		goto exit;

	res = thread_rpc_cmd(OPTEE_RPC_CMD_OCALL, rpc_num_params, rpc_params);
	if (res) {
		/*
		 * Failure to process the OCALL request, as indicated by the
		 * return code of the RPC, denotes that the state of normal
		 * world is such that it may not be able to handle an additional
		 * round-trip to the CA to free the SHM. As such, simply put the
		 * memory object here.
		 */
		mobj_put(mobj);
		return res;
	}

	res = ocall_post_process(rpc_params + 2, ocall_up, mobj_va);
	if (res)
		goto exit;

	params[0].value.a = rpc_params[0].u.value.b;  /* OCALL ret val */
	params[0].value.b = rpc_params[0].u.value.c;  /* OCALL ret val origin */

exit:
	if (mobj)
		thread_rpc_free_client_app_payload(mobj);

	return res;
}
#else
static TEE_Result system_ocall(struct ts_session *cs __unused,
			       uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /*CFG_USER_OCALL*/

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
	case PTA_SYSTEM_OCALL:
		return system_ocall(s, param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SYSTEM_UUID, .name = "system.pta",
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
