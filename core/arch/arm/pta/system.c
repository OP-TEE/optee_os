// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2019, Linaro Limited
 */

#include <crypto/crypto.h>
#include <kernel/handle.h>
#include <kernel/huk_subkey.h>
#include <kernel/misc.h>
#include <kernel/msg_param.h>
#include <kernel/pseudo_ta.h>
#include <kernel/user_ta.h>
#include <kernel/user_ta_store.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/tee_mmu.h>
#include <pta_system.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_defines.h>
#include <util.h>

#define MAX_ENTROPY_IN			32u

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

static TEE_Result system_map_zi(struct tee_ta_session *s, uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE);
	uint32_t flags = TEE_MATTR_URW | TEE_MATTR_PRW;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t pad_begin = 0;
	struct fobj *f = NULL;
	uint32_t pad_end = 0;
	vaddr_t va = 0;

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[0].value.b & ~PTA_SYSTEM_MAP_FLAG_SHAREABLE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.b & PTA_SYSTEM_MAP_FLAG_SHAREABLE)
		flags |= TEE_MATTR_SHAREABLE;

	va = reg_pair_to_64(params[1].value.a, params[1].value.b);
	pad_begin = params[2].value.a;
	pad_end = params[2].value.b;

	f = fobj_ta_mem_alloc(ROUNDUP(params[0].value.a, SMALL_PAGE_SIZE) /
			      SMALL_PAGE_SIZE);
	if (!f)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = user_ta_map(to_user_ta_ctx(s->ctx), &va, f, flags, NULL,
			  pad_begin, pad_end);
	fobj_put(f);

	if (!res)
		reg_pair_from_64(va, &params[1].value.a, &params[1].value.b);

	return res;
}

static TEE_Result system_unmap(struct tee_ta_session *s, uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (exp_pt != param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.b)
		return TEE_ERROR_BAD_PARAMETERS;

	return user_ta_unmap(to_user_ta_ctx(s->ctx),
			     reg_pair_to_64(params[1].value.a,
					    params[1].value.b),
			     ROUNDUP(params[0].value.a, SMALL_PAGE_SIZE));
}

static void ta_bin_close(void *ptr)
{
	struct bin_handle *binh = ptr;

	if (binh) {
		if (binh->op && binh->h)
			binh->op->close(binh->h);
		file_put(binh->f);
	}
	free(binh);
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

	SCATTERED_ARRAY_FOREACH(binh->op, ta_stores, struct user_ta_store_ops) {
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
	size_t l =  num_bytes;

	if (offs_bytes < binh->offs_bytes)
		return TEE_ERROR_BAD_STATE;
	if (offs_bytes > binh->offs_bytes) {
		res = binh->op->read(binh->h, NULL,
				     offs_bytes - binh->offs_bytes);
		if (res)
			return res;
		binh->offs_bytes = offs_bytes;
	}

	if (binh->offs_bytes + l > binh->size_bytes) {
		size_t rb = binh->size_bytes - binh->offs_bytes;

		res = binh->op->read(binh->h, (void *)va, rb);
		if (res)
			return res;
		memset((uint8_t *)va + rb, 0, l - rb);
		binh->offs_bytes = binh->size_bytes;
	} else {
		res = binh->op->read(binh->h, (void *)va, l);
		if (res)
			return res;
		binh->offs_bytes += l;
	}

	return TEE_SUCCESS;
}

static TEE_Result system_map_ta_binary(struct system_ctx *ctx,
				       struct tee_ta_session *s,
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
	struct bin_handle *binh = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct file_slice *fs = NULL;
	bool file_is_locked = false;
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
	num_pages = ROUNDUP(num_bytes, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE;

	if (!file_trylock(binh->f)) {
		/*
		 * Before we can block on the file lock we must make all
		 * our page tables available for reclaiming in order to
		 * avoid a dead-lock with the other thread (which already
		 * is holding the file lock) mapping lots of memory below.
		 */
		tee_mmu_set_ctx(NULL);
		file_lock(binh->f);
		tee_mmu_set_ctx(s->ctx);
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

		res = user_ta_map(to_user_ta_ctx(s->ctx), &va, fs->fobj, prot,
				  binh->f, pad_begin, pad_end);
		if (res)
			goto err;
	} else {
		struct fobj *f = fobj_ta_mem_alloc(num_pages);
		struct file *file = NULL;

		if (!f) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		if (!(flags & PTA_SYSTEM_MAP_FLAG_WRITEABLE))
			file = binh->f;
		res = user_ta_map(to_user_ta_ctx(s->ctx), &va, f,
						 TEE_MATTR_PRW, file,
						 pad_begin, pad_end);
		fobj_put(f);
		if (res)
			goto err;
		res = binh_copy_to(binh, va, offs_bytes, num_bytes);
		if (res)
			goto err_unmap_va;
		res = user_ta_set_prot(to_user_ta_ctx(s->ctx), va,
				       num_pages * SMALL_PAGE_SIZE, prot);
		if (res)
			goto err_unmap_va;

		/*
		 * The context currently is active set it again to update
		 * the mapping.
		 */
		tee_mmu_set_ctx(s->ctx);

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
	if (user_ta_unmap(to_user_ta_ctx(s->ctx), va,
			  num_pages * SMALL_PAGE_SIZE))
		panic();

	/*
	 * The context currently is active set it again to update
	 * the mapping.
	 */
	tee_mmu_set_ctx(s->ctx);

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

static TEE_Result system_set_prot(struct tee_ta_session *s,
				  uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t accept_flags = PTA_SYSTEM_MAP_FLAG_WRITEABLE |
				      PTA_SYSTEM_MAP_FLAG_EXECUTABLE;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	uint32_t prot = TEE_MATTR_UR | TEE_MATTR_PR;
	uint32_t flags = 0;
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

	va = reg_pair_to_64(params[1].value.a, params[1].value.b),
	sz = ROUNDUP(params[0].value.a, SMALL_PAGE_SIZE);

	return user_ta_set_prot(to_user_ta_ctx(s->ctx), va, sz, prot);
}

static TEE_Result open_session(uint32_t param_types __unused,
			       TEE_Param params[TEE_NUM_PARAMS] __unused,
			       void **sess_ctx)
{
	struct tee_ta_session *s = NULL;
	struct system_ctx *ctx = NULL;

	/* Check that we're called from a user TA */
	s = tee_ta_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;
	if (!is_user_ta_ctx(s->ctx))
		return TEE_ERROR_ACCESS_DENIED;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*sess_ctx = ctx;

	return TEE_SUCCESS;
}

static void close_session(void *sess_ctx)
{
	struct system_ctx *ctx = sess_ctx;

	handle_db_destroy(&ctx->db, ta_bin_close);
	free(ctx);
}

static TEE_Result invoke_command(void *sess_ctx, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	struct tee_ta_session *s = tee_ta_get_calling_session();

	switch (cmd_id) {
	case PTA_SYSTEM_ADD_RNG_ENTROPY:
		return system_rng_reseed(s, param_types, params);
	case PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY:
		return system_derive_ta_unique_key(s, param_types, params);
	case PTA_SYSTEM_MAP_ZI:
		return system_map_zi(s, param_types, params);
	case PTA_SYSTEM_UNMAP:
		return system_unmap(s, param_types, params);
	case PTA_SYSTEM_OPEN_TA_BINARY:
		return system_open_ta_binary(sess_ctx, param_types, params);
	case PTA_SYSTEM_CLOSE_TA_BINARY:
		return system_close_ta_binary(sess_ctx, param_types, params);
	case PTA_SYSTEM_MAP_TA_BINARY:
		return system_map_ta_binary(sess_ctx, s, param_types, params);
	case PTA_SYSTEM_COPY_FROM_TA_BINARY:
		return system_copy_from_ta_binary(sess_ctx, param_types,
						  params);
	case PTA_SYSTEM_SET_PROT:
		return system_set_prot(s, param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SYSTEM_UUID, .name = "system.pta",
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
