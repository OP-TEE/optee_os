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

static uint32_t elf_flags_to_mattr(uint32_t flags, bool init_attrs)
{
	uint32_t mattr = 0;

	if (init_attrs)
		mattr = TEE_MATTR_PRW;
	else {
		if (flags & PF_X)
			mattr |= TEE_MATTR_UX;
		if (flags & PF_W)
			mattr |= TEE_MATTR_UW;
		if (flags & PF_R)
			mattr |= TEE_MATTR_UR;
	}

	return mattr;
}

#ifdef CFG_PAGED_USER_TA
static TEE_Result config_initial_paging(struct user_ta_ctx *utc)
{
	size_t n;

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (!utc->mmu->regions[n].size)
			continue;
		if (!tee_pager_add_uta_area(utc, utc->mmu->regions[n].va,
					    utc->mmu->regions[n].size))
			return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

static TEE_Result config_final_paging(struct user_ta_ctx *utc)
{
	size_t n;
	uint32_t flags;

	tee_pager_assign_uta_tables(utc);

	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		if (!utc->mmu->regions[n].size)
			continue;
		flags = utc->mmu->regions[n].attr &
			(TEE_MATTR_PRW | TEE_MATTR_URWX);
		if (!tee_pager_set_uta_area_attr(utc, utc->mmu->regions[n].va,
						 utc->mmu->regions[n].size,
						 flags))
			return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}
#else /*!CFG_PAGED_USER_TA*/
static TEE_Result config_initial_paging(struct user_ta_ctx *utc __unused)
{
	return TEE_SUCCESS;
}

static TEE_Result config_final_paging(struct user_ta_ctx *utc)
{
	void *va = (void *)utc->mmu->ta_private_vmem_start;
	size_t vasize = utc->mmu->ta_private_vmem_end -
			utc->mmu->ta_private_vmem_start;

	cache_op_inner(DCACHE_AREA_CLEAN, va, vasize);
	cache_op_inner(ICACHE_AREA_INVALIDATE, va, vasize);
	return TEE_SUCCESS;
}
#endif /*!CFG_PAGED_USER_TA*/

static TEE_Result load_elf_segments(struct user_ta_ctx *utc,
			struct elf_load_state *elf_state, bool init_attrs)
{
	TEE_Result res;
	uint32_t mattr;
	size_t idx = 0;

	tee_mmu_map_init(utc);

	/*
	 * Add stack segment
	 */
	tee_mmu_map_stack(utc, utc->mobj_stack);

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
			mattr = elf_flags_to_mattr(flags, init_attrs);
			res = tee_mmu_map_add_segment(utc, utc->mobj_code,
						      offs, size, mattr);
			if (res != TEE_SUCCESS)
				return res;
		} else if (type == PT_ARM_EXIDX) {
			utc->exidx_start = offs;
			utc->exidx_size = size;
		}
	}

	if (init_attrs)
		return config_initial_paging(utc);
	else
		return config_final_paging(utc);
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

	/* Currently all TA must execute from DDR */
	if (!(ta_head->flags & TA_FLAG_EXEC_DDR)) {
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	/* Temporary assignment to setup memory mapping */
	utc->ctx.flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;

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

	res = tee_mmu_init(utc);
	if (res != TEE_SUCCESS)
		goto out;

	res = load_elf_segments(utc, elf_state, true /* init attrs */);
	if (res != TEE_SUCCESS)
		goto out;

	tee_mmu_set_ctx(&utc->ctx);

	res = elf_load_body(elf_state, tee_mmu_get_load_addr(&utc->ctx));
	if (res != TEE_SUCCESS)
		goto out;

	/*
	 * Replace the init attributes with attributes used when the TA is
	 * running.
	 */
	res = load_elf_segments(utc, elf_state, false /* final attrs */);
	if (res != TEE_SUCCESS)
		goto out;

out:
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
	uint32_t mandatory_flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;
	uint32_t optional_flags = mandatory_flags | TA_FLAG_SINGLE_INSTANCE |
	    TA_FLAG_MULTI_SESSION | TA_FLAG_SECURE_DATA_PATH |
	    TA_FLAG_INSTANCE_KEEP_ALIVE | TA_FLAG_CACHE_MAINTENANCE;
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

	res = load_elf(utc, ta_store, ta_handle);
	if (res != TEE_SUCCESS)
		goto error_return;

	utc->load_addr = tee_mmu_get_load_addr(&utc->ctx);
	ta_head = (struct ta_head *)(vaddr_t)utc->load_addr;

	if (memcmp(&ta_head->uuid, uuid, sizeof(TEE_UUID)) != 0) {
		res = TEE_ERROR_SECURITY;
		goto error_return;
	}

	/* check input flags bitmask consistency and save flags */
	if ((ta_head->flags & optional_flags) != ta_head->flags ||
	    (ta_head->flags & mandatory_flags) != mandatory_flags) {
		EMSG("TA flag issue: flags=%x optional=%x mandatory=%x",
		     ta_head->flags, optional_flags, mandatory_flags);
		res = TEE_ERROR_BAD_FORMAT;
		goto error_return;
	}

	DMSG("ELF load address 0x%x", utc->load_addr);
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
		tee_mmu_final(utc);
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

	if (!(utc->ctx.flags & TA_FLAG_EXEC_DDR))
		panic("TA does not exec in DDR");

	/* Map user space memory */
	res = tee_mmu_map_param(utc, param, param_va);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	/* Switch to user ctx */
	tee_ta_push_current_session(session);

	/* Make room for usr_params at top of stack */
	usr_stack = (uaddr_t)utc->mmu->regions[TEE_MMU_UMAP_STACK_IDX].va +
		utc->mobj_stack->size;
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
	char flags[4] = { '\0', };
	size_t n;

	EMSG_RAW(" arch: %s  load address: 0x%x  ctx-idr: %d",
		 utc->is_32bit ? "arm" : "aarch64", utc->load_addr,
		 utc->mmu->asid);
	EMSG_RAW(" stack: 0x%" PRIxVA " %zu",
		 utc->mmu->regions[TEE_MMU_UMAP_STACK_IDX].va,
		 utc->mobj_stack->size);
	for (n = 0; n < ARRAY_SIZE(utc->mmu->regions); n++) {
		paddr_t pa = 0;

		if (utc->mmu->regions[n].mobj)
			mobj_get_pa(utc->mmu->regions[n].mobj,
				    utc->mmu->regions[n].offset, 0, &pa);

		mattr_uflags_to_str(flags, sizeof(flags),
				    utc->mmu->regions[n].attr);
		EMSG_RAW(" region %zu: va %#" PRIxVA " pa %#" PRIxPA
			 " size %#zx flags %s",
			 n, utc->mmu->regions[n].va, pa,
			 utc->mmu->regions[n].size, flags);
	}
}
KEEP_PAGER(user_ta_dump_state);

static void user_ta_ctx_destroy(struct tee_ta_ctx *ctx)
{
	struct user_ta_ctx *utc = to_user_ta_ctx(ctx);

	tee_pager_rem_uta_areas(utc);

	/*
	 * Clean all traces of the TA, both RO and RW data.
	 * No L2 cache maintenance to avoid sync problems
	 */
	if (ctx->flags & TA_FLAG_EXEC_DDR) {
		void *va;

		if (utc->mobj_code) {
			va = mobj_get_va(utc->mobj_code, 0);
			if (va) {
				memset(va, 0, utc->mobj_code->size);
				cache_op_inner(DCACHE_AREA_CLEAN, va,
						utc->mobj_code->size);
			}
		}

		if (utc->mobj_stack) {
			va = mobj_get_va(utc->mobj_stack, 0);
			if (va) {
				memset(va, 0, utc->mobj_stack->size);
				cache_op_inner(DCACHE_AREA_CLEAN, va,
						utc->mobj_stack->size);
			}
		}
	}

	/*
	 * Close sessions opened by this TA
	 * Note that tee_ta_close_session() removes the item
	 * from the utc->open_sessions list.
	 */
	while (!TAILQ_EMPTY(&utc->open_sessions)) {
		tee_ta_close_session(TAILQ_FIRST(&utc->open_sessions),
				     &utc->open_sessions, KERN_IDENTITY);
	}

	tee_mmu_final(utc);
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
	return to_user_ta_ctx(ctx)->mmu->asid;
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
		if (res == TEE_SUCCESS)
			s->ctx->ops = &user_ta_ops;
		else
			DMSG("res=0x%x", res);
		return res;
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}
