// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <assert.h>
#include <kernel/ldelf_syscalls.h>
#include <kernel/user_mode_ctx.h>
#include <ldelf.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/vm.h>
#include <pta_system.h>
#include <stdlib.h>
#include <string.h>
#include <trace.h>
#include <util.h>

struct bin_handle {
	const struct ts_store_ops *op;
	struct ts_store_handle *h;
	struct file *f;
	size_t offs_bytes;
	size_t size_bytes;
};

void ta_bin_close(void *ptr)
{
	struct bin_handle *binh = ptr;

	if (binh) {
		if (binh->op && binh->h)
			binh->op->close(binh->h);
		file_put(binh->f);
	}
	free(binh);
}

TEE_Result ldelf_open_ta_binary(struct system_ctx *ctx, uint32_t param_types,
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

	return TEE_SUCCESS;
err_oom:
	res = TEE_ERROR_OUT_OF_MEMORY;
err:
	ta_bin_close(binh);
	return res;
}

TEE_Result ldelf_close_ta_binary(struct system_ctx *ctx, uint32_t param_types,
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

TEE_Result ldelf_map_ta_binary(struct system_ctx *ctx,
			       struct user_mode_ctx *uctx,
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
		vm_set_ctx(uctx->ts_ctx);
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
		res = vm_map_pad(uctx, &va, num_rounded_bytes,
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
		res = vm_map_pad(uctx, &va, num_rounded_bytes,
				 TEE_MATTR_PRW, vm_flags, mobj, 0,
				 pad_begin, pad_end, 0);
		mobj_put(mobj);
		if (res)
			goto err;
		res = binh_copy_to(binh, va, offs_bytes, num_bytes);
		if (res)
			goto err_unmap_va;
		res = vm_set_prot(uctx, va, num_rounded_bytes,
				  prot);
		if (res)
			goto err_unmap_va;

		/*
		 * The context currently is active set it again to update
		 * the mapping.
		 */
		vm_set_ctx(uctx->ts_ctx);

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
	if (vm_unmap(uctx, va, num_rounded_bytes))
		panic();

	/*
	 * The context currently is active set it again to update
	 * the mapping.
	 */
	vm_set_ctx(uctx->ts_ctx);

err:
	if (file_is_locked)
		file_unlock(binh->f);

	return res;
}

TEE_Result ldelf_copy_from_ta_binary(struct system_ctx *ctx,
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

TEE_Result ldelf_set_prot(struct user_mode_ctx *uctx, uint32_t param_types,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t accept_flags = PTA_SYSTEM_MAP_FLAG_WRITEABLE |
				      PTA_SYSTEM_MAP_FLAG_EXECUTABLE;
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
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

	res = vm_get_flags(uctx, va, sz, &vm_flags);
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

	return vm_set_prot(uctx, va, sz, prot);
}

TEE_Result ldelf_remap(struct user_mode_ctx *uctx, uint32_t param_types,
		       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_VALUE_INOUT,
					  TEE_PARAM_TYPE_VALUE_INPUT);
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

	res = vm_get_flags(uctx, old_va, num_bytes, &vm_flags);
	if (res)
		return res;
	if (vm_flags & VM_FLAG_PERMANENT)
		return TEE_ERROR_ACCESS_DENIED;

	res = vm_remap(uctx, &new_va, old_va, num_bytes, pad_begin,
		       pad_end);
	if (!res)
		reg_pair_from_64(new_va, &params[2].value.a,
				 &params[2].value.b);

	return res;
}
