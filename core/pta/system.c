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
#include <pta_system.h>
#include <stdlib_ext.h>
#include <stdlib.h>
#include <string.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_defines.h>
#include <tee/tee_supp_plugin_rpc.h>
#include <tee/uuid.h>
#include <util.h>

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

static TEE_Result system_open_ta_binary(struct system_ctx *ctx,
					uint32_t param_types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	struct bin_handle *binh = NULL;
	int h = 0;
	TEE_UUID *uuid = NULL;
	uint8_t tag[FILE_TAG_SIZE] = { 0 };
	unsigned int tag_len = sizeof(tag);
	struct user_ta_ctx *utc = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].memref.size != sizeof(*uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	uuid = params[0].memref.buffer;

	binh = calloc(1, sizeof(*binh));
	if (!binh)
		return TEE_ERROR_OUT_OF_MEMORY;

	SCATTERED_ARRAY_FOREACH(binh->op, ta_stores, struct ts_store_ops) {
		DMSG("Lookup user TA ELF %pUl (%s)",
		     (void *)uuid, binh->op->description);

		res = binh->op->open(uuid, &binh->h);
		DMSG("res=0x%x", res);
		if (res != TEE_ERROR_ITEM_NOT_FOUND &&
		    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
			break;
	}
	if (res)
		goto err;

	res = binh->op->get_size(binh->h, &binh->size_bytes);
	if (res)
		goto err;
	res = binh->op->get_tag(binh->h, tag, &tag_len);
	if (res)
		goto err;
	binh->f = file_get_by_tag(tag, tag_len);
	if (!binh->f)
		goto err_oom;

	h = handle_get(&ctx->db, binh);
	if (h < 0)
		goto err_oom;
	params[0].value.a = h;

#ifdef CFG_ATTESTATION_PTA
	utc = to_user_ta_ctx(tee_ta_get_calling_session()->ctx);
	memcpy(utc->ta_image_sha256, tag, tag_len);
#endif

	return TEE_SUCCESS;
err_oom:
	res = TEE_ERROR_OUT_OF_MEMORY;
err:
	ta_bin_close(binh);
	return res;
}

static TEE_Result system_close_ta_binary(struct system_ctx *ctx,
					 uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	struct bin_handle *binh = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.b)
		return TEE_ERROR_BAD_PARAMETERS;

	binh = handle_put(&ctx->db, params[0].value.a);
	if (!binh)
		return TEE_ERROR_BAD_PARAMETERS;

	if (binh->offs_bytes < binh->size_bytes)
		res = binh->op->read(binh->h, NULL,
				     binh->size_bytes - binh->offs_bytes);

	ta_bin_close(binh);
	return res;
}

static TEE_Result binh_copy_to(struct bin_handle *binh, vaddr_t va,
			       size_t offs_bytes, size_t num_bytes)
{
	TEE_Result res = TEE_SUCCESS;
	size_t next_offs = 0;

	if (offs_bytes < binh->offs_bytes)
		return TEE_ERROR_BAD_STATE;

	if (ADD_OVERFLOW(offs_bytes, num_bytes, &next_offs))
		return TEE_ERROR_BAD_PARAMETERS;

	if (offs_bytes > binh->offs_bytes) {
		res = binh->op->read(binh->h, NULL,
				     offs_bytes - binh->offs_bytes);
		if (res)
			return res;
		binh->offs_bytes = offs_bytes;
	}

	if (next_offs > binh->size_bytes) {
		size_t rb = binh->size_bytes - binh->offs_bytes;

		res = binh->op->read(binh->h, (void *)va, rb);
		if (res)
			return res;
		memset((uint8_t *)va + rb, 0, num_bytes - rb);
		binh->offs_bytes = binh->size_bytes;
	} else {
		res = binh->op->read(binh->h, (void *)va, num_bytes);
		if (res)
			return res;
		binh->offs_bytes = next_offs;
	}

	return TEE_SUCCESS;
}

static TEE_Result system_map_ta_binary(struct system_ctx *ctx,
				       struct ts_session *s,
				       uint32_t param_types,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t accept_flags = PTA_SYSTEM_MAP_FLAG_SHAREABLE |
				      PTA_SYSTEM_MAP_FLAG_WRITEABLE |
				      PTA_SYSTEM_MAP_FLAG_EXECUTABLE;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_VALUE_INPUT);
	struct user_ta_ctx *utc = to_user_ta_ctx(s->ctx);
	struct bin_handle *binh = NULL;
	uint32_t num_rounded_bytes = 0;
	TEE_Result res = TEE_SUCCESS;
	struct file_slice *fs = NULL;
	bool file_is_locked = false;
	struct mobj *mobj = NULL;
	uint32_t offs_bytes = 0;
	uint32_t offs_pages = 0;
	uint32_t num_bytes = 0;
	uint32_t pad_begin = 0;
	uint32_t pad_end = 0;
	size_t num_pages = 0;
	uint32_t flags = 0;
	uint32_t prot = 0;
	vaddr_t va = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	binh = handle_lookup(&ctx->db, params[0].value.a);
	if (!binh)
		return TEE_ERROR_BAD_PARAMETERS;
	flags = params[0].value.b;
	offs_bytes = params[1].value.a;
	num_bytes = params[1].value.b;
	va = reg_pair_to_64(params[2].value.a, params[2].value.b);
	pad_begin = params[3].value.a;
	pad_end = params[3].value.b;

	if ((flags & accept_flags) != flags)
		return TEE_ERROR_BAD_PARAMETERS;

	if ((flags & PTA_SYSTEM_MAP_FLAG_SHAREABLE) &&
	    (flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((flags & PTA_SYSTEM_MAP_FLAG_EXECUTABLE) &&
	    (flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (offs_bytes & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	prot = TEE_MATTR_UR | TEE_MATTR_PR;
	if (flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE)
		prot |= TEE_MATTR_UW | TEE_MATTR_PW;
	if (flags & PTA_SYSTEM_MAP_FLAG_EXECUTABLE)
		prot |= TEE_MATTR_UX;

	offs_pages = offs_bytes >> SMALL_PAGE_SHIFT;
	if (ROUNDUP_OVERFLOW(num_bytes, SMALL_PAGE_SIZE, &num_rounded_bytes))
		return TEE_ERROR_BAD_PARAMETERS;
	num_pages = num_rounded_bytes / SMALL_PAGE_SIZE;

	if (!file_trylock(binh->f)) {
		/*
		 * Before we can block on the file lock we must make all
		 * our page tables available for reclaiming in order to
		 * avoid a dead-lock with the other thread (which already
		 * is holding the file lock) mapping lots of memory below.
		 */
		vm_set_ctx(NULL);
		file_lock(binh->f);
		vm_set_ctx(s->ctx);
	}
	file_is_locked = true;
	fs = file_find_slice(binh->f, offs_pages);
	if (fs) {
		/* If there's registered slice it has to match */
		if (fs->page_offset != offs_pages ||
		    num_pages > fs->fobj->num_pages) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		/* If there's a slice we must be mapping shareable */
		if (!(flags & PTA_SYSTEM_MAP_FLAG_SHAREABLE)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		mobj = mobj_with_fobj_alloc(fs->fobj, binh->f);
		if (!mobj) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		res = vm_map_pad(&utc->uctx, &va, num_rounded_bytes,
				 prot, VM_FLAG_READONLY,
				 mobj, 0, pad_begin, pad_end, 0);
		mobj_put(mobj);
		if (res)
			goto err;
	} else {
		struct fobj *f = fobj_ta_mem_alloc(num_pages);
		struct file *file = NULL;
		uint32_t vm_flags = 0;

		if (!f) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		if (!(flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE)) {
			file = binh->f;
			vm_flags |= VM_FLAG_READONLY;
		}

		mobj = mobj_with_fobj_alloc(f, file);
		fobj_put(f);
		if (!mobj) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		res = vm_map_pad(&utc->uctx, &va, num_rounded_bytes,
				 TEE_MATTR_PRW, vm_flags, mobj, 0,
				 pad_begin, pad_end, 0);
		mobj_put(mobj);
		if (res)
			goto err;
		res = binh_copy_to(binh, va, offs_bytes, num_bytes);
		if (res)
			goto err_unmap_va;
		res = vm_set_prot(&utc->uctx, va, num_rounded_bytes,
				  prot);
		if (res)
			goto err_unmap_va;

		/*
		 * The context currently is active set it again to update
		 * the mapping.
		 */
		vm_set_ctx(s->ctx);

		if (!(flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE)) {
			res = file_add_slice(binh->f, f, offs_pages);
			if (res)
				goto err_unmap_va;
		}
	}

	file_unlock(binh->f);

	reg_pair_from_64(va, &params[2].value.a, &params[2].value.b);
	return TEE_SUCCESS;

err_unmap_va:
	if (vm_unmap(&utc->uctx, va, num_rounded_bytes))
		panic();

	/*
	 * The context currently is active set it again to update
	 * the mapping.
	 */
	vm_set_ctx(s->ctx);

err:
	if (file_is_locked)
		file_unlock(binh->f);

	return res;
}

static TEE_Result system_copy_from_ta_binary(struct system_ctx *ctx,
					     uint32_t param_types,
					     TEE_Param params[TEE_NUM_PARAMS])
{
	struct bin_handle *binh = NULL;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	binh = handle_lookup(&ctx->db, params[0].value.a);
	if (!binh)
		return TEE_ERROR_BAD_PARAMETERS;

	return binh_copy_to(binh, (vaddr_t)params[1].memref.buffer,
			    params[0].value.b, params[1].memref.size);
}

static TEE_Result system_set_prot(struct ts_session *s,
				  uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t accept_flags = PTA_SYSTEM_MAP_FLAG_WRITEABLE |
				      PTA_SYSTEM_MAP_FLAG_EXECUTABLE;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	struct user_ta_ctx *utc = to_user_ta_ctx(s->ctx);
	uint32_t prot = TEE_MATTR_UR | TEE_MATTR_PR;
	TEE_Result res = TEE_SUCCESS;
	uint32_t vm_flags = 0;
	uint32_t flags = 0;
	vaddr_t end_va = 0;
	vaddr_t va = 0;
	size_t sz = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	flags = params[0].value.b;

	if ((flags & accept_flags) != flags)
		return TEE_ERROR_BAD_PARAMETERS;
	if (flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE)
		prot |= TEE_MATTR_UW | TEE_MATTR_PW;
	if (flags & PTA_SYSTEM_MAP_FLAG_EXECUTABLE)
		prot |= TEE_MATTR_UX;

	va = reg_pair_to_64(params[1].value.a, params[1].value.b);
	sz = ROUNDUP(params[0].value.a, SMALL_PAGE_SIZE);

	/*
	 * The vm_get_flags() and vm_set_prot() are supposed to detect or
	 * handle overflow directly or indirectly. However, this function
	 * an API function so an extra guard here is in order. If nothing
	 * else to make it easier to review the code.
	 */
	if (ADD_OVERFLOW(va, sz, &end_va))
		return TEE_ERROR_BAD_PARAMETERS;

	res = vm_get_flags(&utc->uctx, va, sz, &vm_flags);
	if (res)
		return res;
	if (vm_flags & VM_FLAG_PERMANENT)
		return TEE_ERROR_ACCESS_DENIED;

	/*
	 * If the segment is a mapping of a part of a file (vm_flags &
	 * VM_FLAG_READONLY) it cannot be made writeable as all mapped
	 * files are mapped read-only.
	 */
	if ((vm_flags & VM_FLAG_READONLY) &&
	    (prot & (TEE_MATTR_UW | TEE_MATTR_PW)))
		return TEE_ERROR_ACCESS_DENIED;

	return vm_set_prot(&utc->uctx, va, sz, prot);
}

static TEE_Result system_remap(struct ts_session *s, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_VALUE_INPUT);
	struct user_ta_ctx *utc = to_user_ta_ctx(s->ctx);
	TEE_Result res = TEE_SUCCESS;
	uint32_t num_bytes = 0;
	uint32_t pad_begin = 0;
	uint32_t vm_flags = 0;
	uint32_t pad_end = 0;
	vaddr_t old_va = 0;
	vaddr_t new_va = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	num_bytes = params[0].value.a;
	old_va = reg_pair_to_64(params[1].value.a, params[1].value.b);
	new_va = reg_pair_to_64(params[2].value.a, params[2].value.b);
	pad_begin = params[3].value.a;
	pad_end = params[3].value.b;

	res = vm_get_flags(&utc->uctx, old_va, num_bytes, &vm_flags);
	if (res)
		return res;
	if (vm_flags & VM_FLAG_PERMANENT)
		return TEE_ERROR_ACCESS_DENIED;

	res = vm_remap(&utc->uctx, &new_va, old_va, num_bytes, pad_begin,
		       pad_end);
	if (!res)
		reg_pair_from_64(new_va, &params[2].value.a,
				 &params[2].value.b);

	return res;
}

/* ldelf has the same architecture/register width as the kernel */
#ifdef ARM32
static const bool is_arm32 = true;
#else
static const bool is_arm32;
#endif

static TEE_Result call_ldelf_dlopen(struct user_ta_ctx *utc, TEE_UUID *uuid,
				    uint32_t flags)
{
	uaddr_t usr_stack = utc->uctx.ldelf_stack_ptr;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dl_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;

	assert(uuid);

	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	arg = (struct dl_entry_arg *)usr_stack;

	res = vm_check_access_rights(&utc->uctx,
				     TEE_MEMORY_ACCESS_READ |
				     TEE_MEMORY_ACCESS_WRITE |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)arg, sizeof(*arg));
	if (res) {
		EMSG("ldelf stack is inaccessible!");
		return res;
	}

	memset(arg, 0, sizeof(*arg));
	arg->cmd = LDELF_DL_ENTRY_DLOPEN;
	arg->dlopen.uuid = *uuid;
	arg->dlopen.flags = flags;

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, utc->uctx.dl_entry_func,
				     is_arm32, &panicked, &panic_code);
	if (panicked) {
		EMSG("ldelf dl_entry function panicked");
		abort_print_current_ta();
		res = TEE_ERROR_TARGET_DEAD;
	}
	if (!res)
		res = arg->ret;

	return res;
}

static TEE_Result call_ldelf_dlsym(struct user_ta_ctx *utc, TEE_UUID *uuid,
				   const char *sym, size_t maxlen, vaddr_t *val)
{
	uaddr_t usr_stack = utc->uctx.ldelf_stack_ptr;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dl_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	size_t len = strnlen(sym, maxlen);

	if (len == maxlen)
		return TEE_ERROR_BAD_PARAMETERS;

	usr_stack -= ROUNDUP(sizeof(*arg) + len + 1, STACK_ALIGNMENT);
	arg = (struct dl_entry_arg *)usr_stack;

	res = vm_check_access_rights(&utc->uctx,
				     TEE_MEMORY_ACCESS_READ |
				     TEE_MEMORY_ACCESS_WRITE |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)arg, sizeof(*arg) + len + 1);
	if (res) {
		EMSG("ldelf stack is inaccessible!");
		return res;
	}

	memset(arg, 0, sizeof(*arg));
	arg->cmd = LDELF_DL_ENTRY_DLSYM;
	arg->dlsym.uuid = *uuid;
	memcpy(arg->dlsym.symbol, sym, len);
	arg->dlsym.symbol[len] = '\0';

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, utc->uctx.dl_entry_func,
				     is_arm32, &panicked, &panic_code);
	if (panicked) {
		EMSG("ldelf dl_entry function panicked");
		abort_print_current_ta();
		res = TEE_ERROR_TARGET_DEAD;
	}
	if (!res) {
		res = arg->ret;
		if (!res)
			*val = arg->dlsym.val;
	}

	return res;
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
