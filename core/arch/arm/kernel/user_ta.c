// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2017 Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/user_ta.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <optee_msg_supplicant.h>
#include <signed_hdr.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <ta_pub_key.h>
#include <tee/tee_cryp_utl.h>
#include <tee/tee_obj.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_storage.h>
#include <tee/uuid.h>
#include <trace.h>
#include <types_ext.h>
#include <utee_defines.h>
#include <util.h>

#include "elf_load.h"
#include "elf_common.h"

static void set_ta_ctx_ops(struct tee_ta_ctx *ctx);

static uint32_t elf_flags_to_mattr(uint32_t flags)
{
	uint32_t mattr = 0;

	if (flags & PF_X)
		mattr |= TEE_MATTR_UX;
	if (flags & PF_W)
		mattr |= TEE_MATTR_UW;
	if (flags & PF_R)
		mattr |= TEE_MATTR_UR;

	return mattr;
}

struct load_seg {
	vaddr_t offs;
	uint32_t flags;
	vaddr_t oend;
	vaddr_t va;
	size_t size;
};

static TEE_Result get_elf_segments(struct user_ta_ctx *utc,
				   struct elf_load_state *elf_state,
				   struct load_seg **segs_ret,
				   size_t *num_segs_ret)
{
	TEE_Result res;
	size_t idx = 0;
	size_t num_segs = 0;
	struct load_seg *segs = NULL;

	/*
	 * Add code segment
	 */
	while (true) {
		vaddr_t offs;
		size_t size;
		uint32_t flags;
		uint32_t type;

		res = elf_load_get_next_segment(elf_state, &idx, &offs, &size,
						&flags, &type);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			break;
		if (res != TEE_SUCCESS)
			return res;

		if (type == PT_LOAD) {
			void *p = realloc(segs, (num_segs + 1) * sizeof(*segs));

			if (!p) {
				free(segs);
				return TEE_ERROR_OUT_OF_MEMORY;
			}
			segs = p;
			segs[num_segs].offs = ROUNDDOWN(offs, SMALL_PAGE_SIZE);
			segs[num_segs].oend = ROUNDUP(offs + size,
						      SMALL_PAGE_SIZE);
			segs[num_segs].flags = flags;
			num_segs++;
		} else if (type == PT_ARM_EXIDX) {
			utc->exidx_start = offs;
			utc->exidx_size = size;
		}
	}

	idx = 1;
	while (idx < num_segs) {
		size_t this_size = segs[idx].oend - segs[idx].offs;
		size_t prev_size = segs[idx - 1].oend - segs[idx - 1].offs;

		if (core_is_buffer_intersect(segs[idx].offs, this_size,
					     segs[idx - 1].offs, prev_size)) {
			/* Merge the segments and their attributes */
			segs[idx - 1].oend = MAX(segs[idx - 1].oend,
						 segs[idx].oend);
			segs[idx - 1].flags |= segs[idx].flags;

			/* Remove this index */
			memcpy(segs + idx, segs + idx + 1,
			       (num_segs - idx - 1) * sizeof(*segs));
			num_segs--;
		} else {
			idx++;
		}
	}

	*segs_ret = segs;
	*num_segs_ret = num_segs;
	return TEE_SUCCESS;
}

static struct mobj *alloc_ta_mem(size_t size)
{
#ifdef CFG_PAGED_USER_TA
	return mobj_paged_alloc(size);
#else
	return mobj_mm_alloc(mobj_sec_ddr, size, &tee_mm_sec_ddr);
#endif
}

static TEE_Result load_elf(struct user_ta_ctx *utc,
			   const struct user_ta_store_ops *ta_store,
			   struct user_ta_store_handle *ta_handle)
{
	TEE_Result res;
	struct elf_load_state *elf_state = NULL;
	struct ta_head *ta_head;
	void *p;
	size_t vasize;
	size_t n;
	size_t num_segs = 0;
	struct load_seg *segs = NULL;

	res = elf_load_init(ta_store, ta_handle, &elf_state);
	if (res != TEE_SUCCESS)
		goto out;

	res = elf_load_head(elf_state, sizeof(struct ta_head), &p, &vasize,
			    &utc->is_32bit);
	if (res != TEE_SUCCESS)
		goto out;
	ta_head = p;

	utc->mobj_code = alloc_ta_mem(vasize);
	if (!utc->mobj_code) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Ensure proper aligment of stack */
	utc->mobj_stack = alloc_ta_mem(ROUNDUP(ta_head->stack_size,
					       STACK_ALIGNMENT));
	if (!utc->mobj_stack) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/*
	 * Map physical memory into TA virtual memory
	 */

	res = vm_info_init(utc);
	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * Add stack segment
	 */
	utc->stack_addr = 0;
	res = vm_map(utc, &utc->stack_addr, utc->mobj_stack->size,
		     TEE_MATTR_URW | TEE_MATTR_PRW, utc->mobj_stack, 0);
	if (res)
		goto out;

	res = get_elf_segments(utc, elf_state, &segs, &num_segs);
	if (res != TEE_SUCCESS)
		goto out;

	utc->load_addr = 0;
	for (n = 0; n < num_segs; n++) {
		uint32_t prot = elf_flags_to_mattr(segs[n].flags) |
				TEE_MATTR_PRW;

		segs[n].va = utc->load_addr - segs[0].offs + segs[n].offs;
		segs[n].size = segs[n].oend - segs[n].offs;
		res = vm_map(utc, &segs[n].va, segs[n].size, prot,
			     utc->mobj_code, segs[n].offs);
		if (res)
			goto out;
		if (!n)
			utc->load_addr = segs[0].va;
	}

	tee_mmu_set_ctx(&utc->ctx);

	res = elf_load_body(elf_state, utc->load_addr);
	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * Replace the init attributes with attributes used when the TA is
	 * running.
	 */
	for (n = 0; n < num_segs; n++) {
		res = vm_set_prot(utc, segs[n].va, segs[n].size,
				  elf_flags_to_mattr(segs[n].flags));
		if (res)
			goto out;
	}

out:
	free(segs);
	elf_load_final(elf_state);
	return res;
}

/*-----------------------------------------------------------------------------
 * Loads TA header and hashes.
 * Verifies the TA signature.
 * Returns context ptr and TEE_Result.
 *---------------------------------------------------------------------------*/
static TEE_Result ta_load(const TEE_UUID *uuid,
			  const struct user_ta_store_ops *ta_store,
			  struct tee_ta_ctx **ta_ctx)
{
	TEE_Result res;
	struct user_ta_ctx *utc = NULL;
	struct ta_head *ta_head;
	struct user_ta_store_handle *ta_handle = NULL;

	res = ta_store->open(uuid, &ta_handle);
	if (res != TEE_SUCCESS)
		return res;

	/* Register context */
	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto error_return;
	}
	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);

	/*
	 * Set context TA operation structure. It is required by generic
	 * implementation to identify userland TA versus pseudo TA contexts.
	 */
	set_ta_ctx_ops(&utc->ctx);

	res = load_elf(utc, ta_store, ta_handle);
	if (res != TEE_SUCCESS)
		goto error_return;

	ta_head = (struct ta_head *)(vaddr_t)utc->load_addr;

	if (memcmp(&ta_head->uuid, uuid, sizeof(TEE_UUID)) != 0) {
		res = TEE_ERROR_SECURITY;
		goto error_return;
	}

	if (ta_head->flags & ~TA_FLAGS_MASK) {
		EMSG("Invalid TA flag(s) 0x%" PRIx32,
			ta_head->flags & ~TA_FLAGS_MASK);
		res = TEE_ERROR_BAD_FORMAT;
		goto error_return;
	}

	DMSG("ELF load address %#" PRIxVA, utc->load_addr);
	utc->ctx.flags = ta_head->flags;
	utc->ctx.uuid = ta_head->uuid;
	utc->entry_func = ta_head->entry.ptr64;
	utc->ctx.ref_count = 1;
	condvar_init(&utc->ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->ctx, link);
	*ta_ctx = &utc->ctx;

	tee_mmu_set_ctx(NULL);
	ta_store->close(ta_handle);
	return TEE_SUCCESS;

error_return:
	ta_store->close(ta_handle);
	tee_mmu_set_ctx(NULL);
	if (utc) {
		pgt_flush_ctx(&utc->ctx);
		tee_pager_rem_uta_areas(utc);
		vm_info_final(utc);
		mobj_free(utc->mobj_code);
		mobj_free(utc->mobj_stack);
		free(utc);
	}
	return res;
}

static void init_utee_param(struct utee_params *up,
			const struct tee_ta_param *p, void *va[TEE_NUM_PARAMS])
{
	size_t n;

	up->types = p->types;
	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		uintptr_t a;
		uintptr_t b;

		switch (TEE_PARAM_TYPE_GET(p->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			a = (uintptr_t)va[n];
			b = p->u[n].mem.size;
			break;
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			a = p->u[n].val.a;
			b = p->u[n].val.b;
			break;
		default:
			a = 0;
			b = 0;
			break;
		}
		/* See comment for struct utee_params in utee_types.h */
		up->vals[n * 2] = a;
		up->vals[n * 2 + 1] = b;
	}
}

static void update_from_utee_param(struct tee_ta_param *p,
			const struct utee_params *up)
{
	size_t n;

	for (n = 0; n < TEE_NUM_PARAMS; n++) {
		switch (TEE_PARAM_TYPE_GET(p->types, n)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			/* See comment for struct utee_params in utee_types.h */
			p->u[n].mem.size = up->vals[n * 2 + 1];
			break;
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			/* See comment for struct utee_params in utee_types.h */
			p->u[n].val.a = up->vals[n * 2];
			p->u[n].val.b = up->vals[n * 2 + 1];
			break;
		default:
			break;
		}
	}
}

static void clear_vfp_state(struct user_ta_ctx *utc __unused)
{
#ifdef CFG_WITH_VFP
	thread_user_clear_vfp(&utc->vfp);
#endif
}

static TEE_Result user_ta_enter(TEE_ErrorOrigin *err,
			struct tee_ta_session *session,
			enum utee_entry_func func, uint32_t cmd,
			struct tee_ta_param *param)
{
	TEE_Result res;
	struct utee_params *usr_params;
	uaddr_t usr_stack;
	struct user_ta_ctx *utc = to_user_ta_ctx(session->ctx);
	TEE_ErrorOrigin serr = TEE_ORIGIN_TEE;
	struct tee_ta_session *s __maybe_unused;
	void *param_va[TEE_NUM_PARAMS] = { NULL };

	/* Map user space memory */
	res = tee_mmu_map_param(utc, param, param_va);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	/* Switch to user ctx */
	tee_ta_push_current_session(session);

	/* Make room for usr_params at top of stack */
	usr_stack = utc->stack_addr + utc->mobj_stack->size;
	usr_stack -= ROUNDUP(sizeof(struct utee_params), STACK_ALIGNMENT);
	usr_params = (struct utee_params *)usr_stack;
	init_utee_param(usr_params, param, param_va);

	res = thread_enter_user_mode(func, tee_svc_kaddr_to_uref(session),
				     (vaddr_t)usr_params, cmd, usr_stack,
				     utc->entry_func, utc->is_32bit,
				     &utc->ctx.panicked, &utc->ctx.panic_code);

	clear_vfp_state(utc);
	/*
	 * According to GP spec the origin should allways be set to the
	 * TA after TA execution
	 */
	serr = TEE_ORIGIN_TRUSTED_APP;

	if (utc->ctx.panicked) {
		DMSG("tee_user_ta_enter: TA panicked with code 0x%x\n",
		     utc->ctx.panic_code);
		serr = TEE_ORIGIN_TEE;
		res = TEE_ERROR_TARGET_DEAD;
	}

	/* Copy out value results */
	update_from_utee_param(param, usr_params);

	s = tee_ta_pop_current_session();
	assert(s == session);
cleanup_return:

	/*
	 * Clear the cancel state now that the user TA has returned. The next
	 * time the TA will be invoked will be with a new operation and should
	 * not have an old cancellation pending.
	 */
	session->cancel = false;

	/*
	 * Can't update *err until now since it may point to an address
	 * mapped for the user mode TA.
	 */
	*err = serr;

	return res;
}

static TEE_Result user_ta_enter_open_session(struct tee_ta_session *s,
			struct tee_ta_param *param, TEE_ErrorOrigin *eo)
{
	return user_ta_enter(eo, s, UTEE_ENTRY_FUNC_OPEN_SESSION, 0, param);
}

static TEE_Result user_ta_enter_invoke_cmd(struct tee_ta_session *s,
			uint32_t cmd, struct tee_ta_param *param,
			TEE_ErrorOrigin *eo)
{
	return user_ta_enter(eo, s, UTEE_ENTRY_FUNC_INVOKE_COMMAND, cmd, param);
}

static void user_ta_enter_close_session(struct tee_ta_session *s)
{
	TEE_ErrorOrigin eo;
	struct tee_ta_param param = { 0 };

	user_ta_enter(&eo, s, UTEE_ENTRY_FUNC_CLOSE_SESSION, 0, &param);
}

static void user_ta_dump_state(struct tee_ta_ctx *ctx)
{
	struct user_ta_ctx *utc __maybe_unused = to_user_ta_ctx(ctx);
	struct vm_region *r;
	char flags[7] = { '\0', };
	size_t n = 0;

	EMSG_RAW(" arch: %s  load address: %#" PRIxVA " ctx-idr: %d",
		 utc->is_32bit ? "arm" : "aarch64", utc->load_addr,
		 utc->vm_info->asid);
	EMSG_RAW(" stack: 0x%" PRIxVA " %zu",
		 utc->stack_addr, utc->mobj_stack->size);
	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		paddr_t pa = 0;

		if (r->mobj)
			mobj_get_pa(r->mobj, r->offset, 0, &pa);

		mattr_perm_to_str(flags, sizeof(flags), r->attr);
		EMSG_RAW(" region %zu: va %#" PRIxVA " pa %#" PRIxPA
			 " size %#zx flags %s",
			 n, r->va, pa, r->size, flags);
		n++;
	}
}
KEEP_PAGER(user_ta_dump_state);

static void release_ta_memory_by_mobj(struct mobj *mobj)
{
	void *va;

	if (!mobj)
		return;

	va = mobj_get_va(mobj, 0);
	if (!va)
		return;

	memset(va, 0, mobj->size);
	cache_op_inner(DCACHE_AREA_CLEAN, va, mobj->size);
}

static void user_ta_ctx_destroy(struct tee_ta_ctx *ctx)
{
	struct user_ta_ctx *utc = to_user_ta_ctx(ctx);

	tee_pager_rem_uta_areas(utc);
	release_ta_memory_by_mobj(utc->mobj_code);
	release_ta_memory_by_mobj(utc->mobj_stack);

	/*
	 * Close sessions opened by this TA
	 * Note that tee_ta_close_session() removes the item
	 * from the utc->open_sessions list.
	 */
	while (!TAILQ_EMPTY(&utc->open_sessions)) {
		tee_ta_close_session(TAILQ_FIRST(&utc->open_sessions),
				     &utc->open_sessions, KERN_IDENTITY);
	}

	vm_info_final(utc);
	mobj_free(utc->mobj_code);
	mobj_free(utc->mobj_stack);

	/* Free cryp states created by this TA */
	tee_svc_cryp_free_states(utc);
	/* Close cryp objects opened by this TA */
	tee_obj_close_all(utc);
	/* Free emums created by this TA */
	tee_svc_storage_close_all_enum(utc);
	free(utc);
}

static uint32_t user_ta_get_instance_id(struct tee_ta_ctx *ctx)
{
	return to_user_ta_ctx(ctx)->vm_info->asid;
}

static const struct tee_ta_ops user_ta_ops __rodata_unpaged = {
	.enter_open_session = user_ta_enter_open_session,
	.enter_invoke_cmd = user_ta_enter_invoke_cmd,
	.enter_close_session = user_ta_enter_close_session,
	.dump_state = user_ta_dump_state,
	.destroy = user_ta_ctx_destroy,
	.get_instance_id = user_ta_get_instance_id,
};

static SLIST_HEAD(uta_stores_head, user_ta_store_ops) uta_store_list =
		SLIST_HEAD_INITIALIZER(uta_stores_head);

static void set_ta_ctx_ops(struct tee_ta_ctx *ctx)
{
	ctx->ops = &user_ta_ops;
}

bool is_user_ta_ctx(struct tee_ta_ctx *ctx)
{
	return ctx->ops == &user_ta_ops;
}

TEE_Result tee_ta_register_ta_store(struct user_ta_store_ops *ops)
{
	struct user_ta_store_ops *p = NULL;
	struct user_ta_store_ops *e;

	DMSG("Registering TA store: '%s' (priority %d)", ops->description,
	     ops->priority);

	SLIST_FOREACH(e, &uta_store_list, link) {
		/*
		 * Do not allow equal priorities to avoid any dependency on
		 * registration order.
		 */
		assert(e->priority != ops->priority);
		if (e->priority > ops->priority)
			break;
		p = e;
	}
	if (p)
		SLIST_INSERT_AFTER(p, ops, link);
	else
		SLIST_INSERT_HEAD(&uta_store_list, ops, link);

	return TEE_SUCCESS;
}

TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s)
{
	const struct user_ta_store_ops *store;
	TEE_Result res;

	SLIST_FOREACH(store, &uta_store_list, link) {
		DMSG("Lookup user TA %pUl (%s)", (void *)uuid,
		     store->description);
		res = ta_load(uuid, store, &s->ctx);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			continue;
		if (res != TEE_SUCCESS)
			DMSG("res=0x%x", res);
		return res;
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}
