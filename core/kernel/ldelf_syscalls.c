// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2019, 2022 Linaro Limited
 * Copyright (c) 2020-2021, Arm Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <kernel/ldelf_syscalls.h>
#include <kernel/user_access.h>
#include <kernel/user_mode_ctx.h>
#include <ldelf.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/vm.h>
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

static void unmap_or_panic(struct user_mode_ctx *uctx, vaddr_t va,
			   size_t byte_count)
{
	TEE_Result res = vm_unmap(uctx, va, byte_count);

	if (res) {
		EMSG("vm_unmap(%#"PRIxVA", %#zx) returned %#"PRIx32,
		     va, byte_count, res);
		panic("Can't restore memory map");
	}
}

TEE_Result ldelf_syscall_map_zi(vaddr_t *va, size_t num_bytes, size_t pad_begin,
				size_t pad_end, unsigned long flags)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(sess->ctx);
	struct fobj *f = NULL;
	struct mobj *mobj = NULL;
	uint32_t prot = TEE_MATTR_URW | TEE_MATTR_PRW;
	uint32_t vm_flags = 0;
	vaddr_t va_copy = 0;

	if (flags & ~LDELF_MAP_FLAG_SHAREABLE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = GET_USER_SCALAR(va_copy, va);
	if (res)
		return res;

	if (flags & LDELF_MAP_FLAG_SHAREABLE)
		vm_flags |= VM_FLAG_SHAREABLE;

	f = fobj_ta_mem_alloc(ROUNDUP_DIV(num_bytes, SMALL_PAGE_SIZE));
	if (!f)
		return TEE_ERROR_OUT_OF_MEMORY;
	mobj = mobj_with_fobj_alloc(f, NULL, TEE_MATTR_MEM_TYPE_TAGGED);
	fobj_put(f);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = vm_map_pad(uctx, &va_copy, num_bytes, prot, vm_flags,
			 mobj, 0, pad_begin, pad_end, 0);
	mobj_put(mobj);
	if (!res) {
		res = PUT_USER_SCALAR(va_copy, va);
		if (res)
			unmap_or_panic(uctx, va_copy, num_bytes);
	}

	return res;
}

TEE_Result ldelf_syscall_unmap(vaddr_t va, size_t num_bytes)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(sess->ctx);
	size_t sz = ROUNDUP(num_bytes, SMALL_PAGE_SIZE);
	uint32_t vm_flags = 0;
	vaddr_t end_va = 0;

	/*
	 * The vm_get_flags() and vm_unmap() are supposed to detect or handle
	 * overflow directly or indirectly. However, since this function is an
	 * API function it's worth having an extra guard here. If nothing else,
	 * to increase code clarity.
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

static void bin_close(void *ptr)
{
	struct bin_handle *binh = ptr;

	if (binh) {
		if (binh->op && binh->h)
			binh->op->close(binh->h);
		file_put(binh->f);
	}
	free(binh);
}

TEE_Result ldelf_syscall_open_bin(const TEE_UUID *uuid, size_t uuid_size,
				  uint32_t *handle)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(sess->ctx);
	struct system_ctx *sys_ctx = sess->user_ctx;
	struct bin_handle *binh = NULL;
	uint8_t tag[FILE_TAG_SIZE] = { 0 };
	unsigned int tag_len = sizeof(tag);
	TEE_UUID *bb_uuid = NULL;
	int h = 0;

	res = BB_MEMDUP_USER(uuid, sizeof(*uuid), &bb_uuid);
	if (res)
		return res;

	res = vm_check_access_rights(uctx,
				     TEE_MEMORY_ACCESS_WRITE |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)handle, sizeof(uint32_t));
	if (res)
		return res;

	if (uuid_size != sizeof(*uuid))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!sys_ctx) {
		sys_ctx = calloc(1, sizeof(*sys_ctx));
		if (!sys_ctx)
			return TEE_ERROR_OUT_OF_MEMORY;
		sess->user_ctx = sys_ctx;
	}

	binh = calloc(1, sizeof(*binh));
	if (!binh)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (is_user_ta_ctx(sess->ctx) || is_stmm_ctx(sess->ctx)) {
		SCATTERED_ARRAY_FOREACH(binh->op, ta_stores,
					struct ts_store_ops) {
			DMSG("Lookup user TA ELF %pUl (%s)",
			     (void *)bb_uuid, binh->op->description);

			res = binh->op->open(bb_uuid, &binh->h);
			DMSG("res=%#"PRIx32, res);
			if (res != TEE_ERROR_ITEM_NOT_FOUND &&
			    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
				break;
		}
	} else if (is_sp_ctx(sess->ctx)) {
		SCATTERED_ARRAY_FOREACH(binh->op, sp_stores,
					struct ts_store_ops) {
			DMSG("Lookup user SP ELF %pUl (%s)",
			     (void *)bb_uuid, binh->op->description);

			res = binh->op->open(bb_uuid, &binh->h);
			DMSG("res=%#"PRIx32, res);
			if (res != TEE_ERROR_ITEM_NOT_FOUND &&
			    res != TEE_ERROR_STORAGE_NOT_AVAILABLE)
				break;
		}
	} else {
		res = TEE_ERROR_ITEM_NOT_FOUND;
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

	h = handle_get(&sys_ctx->db, binh);
	if (h < 0)
		goto err_oom;
	res = PUT_USER_SCALAR(h, handle);
	if (res) {
		handle_put(&sys_ctx->db, h);
		goto err;
	}

	return TEE_SUCCESS;

err_oom:
	res = TEE_ERROR_OUT_OF_MEMORY;
err:
	bin_close(binh);
	return res;
}

TEE_Result ldelf_syscall_close_bin(unsigned long handle)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct system_ctx *sys_ctx = sess->user_ctx;
	struct bin_handle *binh = NULL;

	if (!sys_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	binh = handle_put(&sys_ctx->db, handle);
	if (!binh)
		return TEE_ERROR_BAD_PARAMETERS;

	if (binh->offs_bytes < binh->size_bytes)
		res = binh->op->read(binh->h, NULL, NULL,
				     binh->size_bytes - binh->offs_bytes);

	bin_close(binh);
	if (handle_db_is_empty(&sys_ctx->db)) {
		handle_db_destroy(&sys_ctx->db, bin_close);
		free(sys_ctx);
		sess->user_ctx = NULL;
	}

	return res;
}

static TEE_Result binh_copy_to(struct bin_handle *binh, vaddr_t va_core,
			       vaddr_t va_user, size_t offs_bytes,
			       size_t num_bytes)
{
	TEE_Result res = TEE_SUCCESS;
	size_t next_offs = 0;

	if (offs_bytes < binh->offs_bytes)
		return TEE_ERROR_BAD_STATE;

	if (ADD_OVERFLOW(offs_bytes, num_bytes, &next_offs))
		return TEE_ERROR_BAD_PARAMETERS;

	if (offs_bytes > binh->offs_bytes) {
		res = binh->op->read(binh->h, NULL, NULL,
				     offs_bytes - binh->offs_bytes);
		if (res)
			return res;
		binh->offs_bytes = offs_bytes;
	}

	if (next_offs > binh->size_bytes) {
		size_t rb = binh->size_bytes - binh->offs_bytes;

		res = binh->op->read(binh->h, (void *)va_core,
				     (void *)va_user, rb);
		if (res)
			return res;
		if (va_core)
			memset((uint8_t *)va_core + rb, 0, num_bytes - rb);
		if (va_user) {
			res = clear_user((uint8_t *)va_user + rb,
					 num_bytes - rb);
			if (res)
				return res;
		}
		binh->offs_bytes = binh->size_bytes;
	} else {
		res = binh->op->read(binh->h, (void *)va_core,
				     (void *)va_user, num_bytes);
		if (res)
			return res;
		binh->offs_bytes = next_offs;
	}

	return TEE_SUCCESS;
}

TEE_Result ldelf_syscall_map_bin(vaddr_t *va, size_t num_bytes,
				 unsigned long handle, size_t offs_bytes,
				 size_t pad_begin, size_t pad_end,
				 unsigned long flags)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(sess->ctx);
	struct system_ctx *sys_ctx = sess->user_ctx;
	struct bin_handle *binh = NULL;
	uint32_t num_rounded_bytes = 0;
	struct file_slice *fs = NULL;
	bool file_is_locked = false;
	struct mobj *mobj = NULL;
	uint32_t offs_pages = 0;
	size_t num_pages = 0;
	vaddr_t va_copy = 0;
	uint32_t prot = 0;
	const uint32_t accept_flags = LDELF_MAP_FLAG_SHAREABLE |
				      LDELF_MAP_FLAG_WRITEABLE |
				      LDELF_MAP_FLAG_BTI |
				      LDELF_MAP_FLAG_EXECUTABLE;

	res = GET_USER_SCALAR(va_copy, va);
	if (res)
		return res;

	if (!sys_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	binh = handle_lookup(&sys_ctx->db, handle);
	if (!binh)
		return TEE_ERROR_BAD_PARAMETERS;

	if ((flags & accept_flags) != flags)
		return TEE_ERROR_BAD_PARAMETERS;

	if ((flags & LDELF_MAP_FLAG_SHAREABLE) &&
	    (flags & LDELF_MAP_FLAG_WRITEABLE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((flags & LDELF_MAP_FLAG_EXECUTABLE) &&
	    (flags & LDELF_MAP_FLAG_WRITEABLE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (offs_bytes & SMALL_PAGE_MASK)
		return TEE_ERROR_BAD_PARAMETERS;

	prot = TEE_MATTR_UR | TEE_MATTR_PR;
	if (flags & LDELF_MAP_FLAG_WRITEABLE)
		prot |= TEE_MATTR_UW | TEE_MATTR_PW;
	if (flags & LDELF_MAP_FLAG_EXECUTABLE)
		prot |= TEE_MATTR_UX;
	if (flags & LDELF_MAP_FLAG_BTI)
		prot |= TEE_MATTR_GUARDED;

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
		if (!(flags & LDELF_MAP_FLAG_SHAREABLE)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto err;
		}

		mobj = mobj_with_fobj_alloc(fs->fobj, binh->f,
					    TEE_MATTR_MEM_TYPE_TAGGED);
		if (!mobj) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		res = vm_map_pad(uctx, &va_copy, num_rounded_bytes,
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
		if (!(flags & LDELF_MAP_FLAG_WRITEABLE)) {
			file = binh->f;
			vm_flags |= VM_FLAG_READONLY;
		}

		mobj = mobj_with_fobj_alloc(f, file, TEE_MATTR_MEM_TYPE_TAGGED);
		fobj_put(f);
		if (!mobj) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto err;
		}
		res = vm_map_pad(uctx, &va_copy, num_rounded_bytes,
				 TEE_MATTR_PRW, vm_flags, mobj, 0,
				 pad_begin, pad_end, 0);
		mobj_put(mobj);
		if (res)
			goto err;
		res = binh_copy_to(binh, va_copy, 0, offs_bytes, num_bytes);
		if (res)
			goto err_unmap_va;
		res = vm_set_prot(uctx, va_copy, num_rounded_bytes,
				  prot);
		if (res)
			goto err_unmap_va;

		/*
		 * The context currently is active set it again to update
		 * the mapping.
		 */
		vm_set_ctx(uctx->ts_ctx);

		if (!(flags & LDELF_MAP_FLAG_WRITEABLE)) {
			res = file_add_slice(binh->f, f, offs_pages);
			if (res)
				goto err_unmap_va;
		}
	}

	res = PUT_USER_SCALAR(va_copy, va);
	if (res)
		goto err_unmap_va;

	file_unlock(binh->f);

	return TEE_SUCCESS;

err_unmap_va:
	unmap_or_panic(uctx, va_copy, num_rounded_bytes);

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

TEE_Result ldelf_syscall_copy_from_bin(void *dst, size_t offs, size_t num_bytes,
				       unsigned long handle)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(sess->ctx);
	struct system_ctx *sys_ctx = sess->user_ctx;
	struct bin_handle *binh = NULL;

	res = vm_check_access_rights(uctx,
				     TEE_MEMORY_ACCESS_WRITE |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)dst, num_bytes);
	if (res)
		return res;

	if (!sys_ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	binh = handle_lookup(&sys_ctx->db, handle);
	if (!binh)
		return TEE_ERROR_BAD_PARAMETERS;

	return binh_copy_to(binh, 0, (vaddr_t)dst, offs, num_bytes);
}

TEE_Result ldelf_syscall_set_prot(unsigned long va, size_t num_bytes,
				  unsigned long flags)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(sess->ctx);
	size_t sz = ROUNDUP(num_bytes, SMALL_PAGE_SIZE);
	uint32_t prot = TEE_MATTR_UR | TEE_MATTR_PR;
	uint32_t vm_flags = 0;
	vaddr_t end_va = 0;
	const uint32_t accept_flags = LDELF_MAP_FLAG_WRITEABLE |
				      LDELF_MAP_FLAG_BTI |
				      LDELF_MAP_FLAG_EXECUTABLE;

	if ((flags & accept_flags) != flags)
		return TEE_ERROR_BAD_PARAMETERS;
	if (flags & LDELF_MAP_FLAG_WRITEABLE)
		prot |= TEE_MATTR_UW | TEE_MATTR_PW;
	if (flags & LDELF_MAP_FLAG_EXECUTABLE)
		prot |= TEE_MATTR_UX;
	if (flags & LDELF_MAP_FLAG_BTI)
		prot |= TEE_MATTR_GUARDED;

	/*
	 * The vm_get_flags() and vm_unmap() are supposed to detect or handle
	 * overflow directly or indirectly. However, since this function is an
	 * API function it's worth having an extra guard here. If nothing else,
	 * to increase code clarity.
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

TEE_Result ldelf_syscall_remap(unsigned long old_va, vaddr_t *new_va,
			       size_t num_bytes, size_t pad_begin,
			       size_t pad_end)
{
	TEE_Result res = TEE_SUCCESS;
	struct ts_session *sess = ts_get_current_session();
	struct user_mode_ctx *uctx = to_user_mode_ctx(sess->ctx);
	uint32_t vm_flags = 0;
	vaddr_t va_copy = 0;

	res = GET_USER_SCALAR(va_copy, new_va);
	if (res)
		return res;
	res = vm_get_flags(uctx, old_va, num_bytes, &vm_flags);
	if (res)
		return res;
	if (vm_flags & VM_FLAG_PERMANENT)
		return TEE_ERROR_ACCESS_DENIED;

	res = vm_remap(uctx, &va_copy, old_va, num_bytes, pad_begin, pad_end);
	if (res)
		return res;

	res = PUT_USER_SCALAR(va_copy, new_va);
	if (res) {
		TEE_Result res2 = TEE_SUCCESS;
		vaddr_t va = old_va;

		res2 = vm_remap(uctx, &va, va_copy, num_bytes, 0, 0);
		if (res2) {
			EMSG("vm_remap(%#"PRIxVA", %#"PRIxVA", %#zx) returned %#"PRIx32,
			     va, va_copy, num_bytes, res2);
			panic("Can't restore memory map");
		}
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result ldelf_syscall_gen_rnd_num(void *buf, size_t num_bytes)
{
	TEE_Result res = TEE_SUCCESS;
	void *bb = NULL;

	bb = bb_alloc(num_bytes);
	if (!bb)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = crypto_rng_read(bb, num_bytes);
	if (res)
		return res;

	return copy_to_user(buf, bb, num_bytes);
}

/*
 * Should be called after returning from ldelf. If user_ctx is not NULL means
 * that ldelf crashed or otherwise didn't complete properly. This function will
 * close the remaining handles and free the context structs allocated by ldelf.
 */
void ldelf_sess_cleanup(struct ts_session *sess)
{
	struct system_ctx *sys_ctx = sess->user_ctx;

	if (sys_ctx) {
		handle_db_destroy(&sys_ctx->db, bin_close);
		free(sys_ctx);
		sess->user_ctx = NULL;
	}
}
