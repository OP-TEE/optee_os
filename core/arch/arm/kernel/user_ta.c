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


/* ELF file used by a TA (main executable or dynamic library) */
struct user_ta_elf {
	TEE_UUID uuid;
	bool is_main; /* false for a library */
	struct elf_load_state *elf_state;
	struct mobj *mobj_code;
	uaddr_t exidx_start; /* Exception index table (32-bit only) */
	size_t exidx_size;
	TAILQ_ENTRY(user_ta_elf) link;
};

static void free_elfs(struct user_ta_elf_head *elfs)
{
	struct user_ta_elf *elf;
	struct user_ta_elf *next;

	TAILQ_FOREACH_SAFE(elf, elfs, link, next) {
		TAILQ_REMOVE(elfs, elf, link);
		mobj_free(elf->mobj_code);
		free(elf);
	}
}

static struct user_ta_elf *find_ta_elf(const TEE_UUID *uuid,
				       struct user_ta_ctx *utc)
{
	struct user_ta_elf *elf;

	TAILQ_FOREACH(elf, &utc->elfs, link)
		if (!memcmp(&elf->uuid, uuid, sizeof(*uuid)))
			return elf;
	return NULL;
}

static struct user_ta_elf *ta_elf(const TEE_UUID *uuid,
				  struct user_ta_ctx *utc)
{
	struct user_ta_elf *elf;

	elf = find_ta_elf(uuid, utc);
	if (elf)
		goto out;
	elf = calloc(1, sizeof(*elf));
	if (!elf)
		goto out;
	elf->uuid = *uuid;

	TAILQ_INSERT_TAIL(&utc->elfs, elf, link);
out:
	return elf;
}

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
				    struct user_ta_elf *elf,
				    bool init_attrs)
{
	struct elf_load_state *elf_state = elf->elf_state;
	TEE_Result res;
	uint32_t mattr;
	size_t idx = 0;

	if (elf->is_main) {
		tee_mmu_map_init(utc);
		tee_mmu_map_stack(utc, utc->mobj_stack);
	}

	/*
	 * Add code segment
	 */
	while (true) {
		vaddr_t vaddr;
		size_t size;
		uint32_t flags;
		uint32_t type;

		res = elf_load_get_next_segment(elf_state, &idx, &vaddr, &size,
						&flags, &type);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			break;
		if (res != TEE_SUCCESS)
			return res;

		if (type == PT_LOAD) {
			if (!elf->is_main) {
				/* TODO */
				continue;
			}
			mattr = elf_flags_to_mattr(flags, init_attrs);
			res = tee_mmu_map_add_segment(utc, elf->mobj_code,
						      vaddr, size, mattr);
			if (res != TEE_SUCCESS)
				return res;
		} else if (type == PT_ARM_EXIDX) {
			elf->exidx_start = vaddr;
			elf->exidx_size = size;
			if (elf->is_main) {
				/* TODO */
				utc->exidx_start = vaddr;
				utc->exidx_size = size;
			}
		}
	}

	/* TODO */
	if (!elf->is_main)
		return TEE_SUCCESS;

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
	char flags[7] = { '\0', };
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

		mattr_perm_to_str(flags, sizeof(flags),
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
	struct user_ta_elf *elf;

	tee_pager_rem_uta_areas(utc);

	/*
	 * Clean all traces of the TA, both RO and RW data.
	 * No L2 cache maintenance to avoid sync problems
	 */
	if (ctx->flags & TA_FLAG_EXEC_DDR) {
		void *va;

		TAILQ_FOREACH(elf, &utc->elfs, link) {
			va = mobj_get_va(elf->mobj_code, 0);
			if (va) {
				memset(va, 0, elf->mobj_code->size);
				cache_op_inner(DCACHE_AREA_CLEAN, va,
					       elf->mobj_code->size);
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
	mobj_free(utc->mobj_stack);
	free_elfs(&utc->elfs);

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

static char tolowercase(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

static int8_t hex(char c)
{
	char lc = tolowercase(c);

	if (lc >= '0' && lc <= '9')
		return (int8_t)(lc - '0');
	if (lc >= 'a' && lc <= 'f')
		return (int8_t)(lc - 'a' + 10);
	return -1;
}

static uint32_t parse_hex(const char *s, size_t nchars, uint32_t *res)
{
	uint32_t v = 0;
	size_t n;
	char c;

	for (n = 0; n < nchars; n++) {
		c = hex(s[n]);
		if (c == (char)-1) {
			*res = TEE_ERROR_BAD_FORMAT;
			goto out;
		}
		v = (v << 4) + c;
	}
	*res = TEE_SUCCESS;
out:
	return v;
}

/*
 * Convert a UUID string @s into a TEE_UUID @uuid
 * Expected format for @s is: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
 * 'x' being any hexadecimal digit (0-9a-fA-F)
 */
static TEE_Result parse_uuid(const char *s, TEE_UUID *uuid)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_UUID u = { 0 };
	const char *p = s;
	size_t i;

	if (strlen(p) != 36)
		return TEE_ERROR_BAD_FORMAT;
	if (p[8] != '-' || p[13] != '-' || p[18] != '-' || p[23] != '-')
		return TEE_ERROR_BAD_FORMAT;

	u.timeLow = parse_hex(p, 8, &res);
	if (res)
		goto out;
	p += 9;
	u.timeMid = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	u.timeHiAndVersion = parse_hex(p, 4, &res);
	if (res)
		goto out;
	p += 5;
	for (i = 0; i < 8; i++) {
		u.clockSeqAndNode[i] = parse_hex(p, 2, &res);
		if (res)
			goto out;
		if (i == 1)
			p += 3;
		else
			p += 2;
	}
	*uuid = u;
out:
	return res;
}

static TEE_Result add_elf_deps(struct user_ta_ctx *utc, char **deps)
{
	struct user_ta_elf *libelf;
	TEE_Result res = TEE_SUCCESS;
	TEE_UUID u;
	char **s;

	for (s = deps; s && *s; s++) {
		res = parse_uuid(*s, &u);
		if (res) {
			EMSG("Invalid dependency (not a UUID): %s", *s);
			goto out;
		}
		DMSG("Library needed: %pUl", (void *)&u);
		libelf = ta_elf(&u, utc);
		if (!libelf) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}
out:
	return res;
}

static TEE_Result resolve_symbol(struct user_ta_elf_head *elfs,
				 const char *name, uintptr_t *val)
{
	struct user_ta_elf *elf;
	TEE_Result res;

	/*
	 * The loop naturally implements a breadth first search due to the
	 * order in which the libraries were added.
	 */
	TAILQ_FOREACH(elf, elfs, link) {
		res = elf_resolve_symbol(elf->elf_state, name, val);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			continue;
		if (res)
			return res;
		FMSG("%pUl/0x%" PRIxPTR " %s", (void *)&elf->uuid, *val, name);
		return TEE_SUCCESS;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result load_elf_from_store(const TEE_UUID *uuid,
				      const struct user_ta_store_ops *ta_store,
				      struct user_ta_ctx *utc)
{
	struct user_ta_store_handle *handle = NULL;
	struct elf_load_state *elf_state = NULL;
	struct ta_head *ta_head;
	struct user_ta_elf *elf;
	char **deps = NULL;
	uintptr_t vabase;
	TEE_Result res;
	size_t vasize;
	void *p;

	res = ta_store->open(uuid, &handle);
	if (res)
		return res;

	elf = ta_elf(uuid, utc);
	if (!elf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = elf_load_init(ta_store, handle, elf->is_main, &utc->elfs,
			    resolve_symbol, &elf_state);
	if (res)
		goto out;
	elf->elf_state = elf_state;

	res = elf_load_head(elf_state, elf->is_main ? sizeof(struct ta_head)
			    : 0, &p, &vasize, &utc->is_32bit);
	if (res)
		goto out;
	ta_head = p;

	elf->mobj_code = alloc_ta_mem(vasize);
	if (!elf->mobj_code) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (elf->is_main) {
		/*
		 * Add stack segment.
		 */

		/* Ensure proper aligment of stack */
		utc->mobj_stack = alloc_ta_mem(ROUNDUP(ta_head->stack_size,
						       STACK_ALIGNMENT));
		if (!utc->mobj_stack) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	res = load_elf_segments(utc, elf, true /* init attrs */);
	if (res)
		goto out;

	/* TODO: FIXME */
	if (elf->is_main) {
		tee_mmu_set_ctx(&utc->ctx);
		vabase = tee_mmu_get_load_addr(&utc->ctx);
	} else {
		vabase = (vaddr_t)mobj_get_va(elf->mobj_code, 0);
	}

	res = elf_load_body(elf_state, vabase);
	if (res)
		goto out;

	/* Find any external dependency (dynamically linked libraries) */
	res = elf_get_needed(elf_state, vabase, &deps);
	if (res)
		goto out;

	res = add_elf_deps(utc, deps);

out:
	ta_store->close(handle);
	free(deps);
	/* utc is cleaned by caller on error */
	return res;
}

/* Loads a single ELF file (main executable or library) */
static TEE_Result load_elf(const TEE_UUID *uuid, struct user_ta_ctx *utc)
{
	const struct user_ta_store_ops *store;
	TEE_Result res;

	SLIST_FOREACH(store, &uta_store_list, link) {
		DMSG("Lookup user TA ELF %pUl (%s)", (void *)uuid,
		     store->description);
		res = load_elf_from_store(uuid, store, utc);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			continue;
		if (res)
			DMSG("res=0x%x", res);
		return res;
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

static void free_elf_states(struct user_ta_ctx *utc)
{
	struct user_ta_elf *elf;

	TAILQ_FOREACH(elf, &utc->elfs, link)
		elf_load_final(elf->elf_state);
}

/*
 * Loads a TA (statically or dynamically linked)
 */
static TEE_Result ta_load(const TEE_UUID *uuid, struct tee_ta_ctx **ta_ctx)
{
	uint32_t mandatory_flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;
	uint32_t optional_flags = mandatory_flags | TA_FLAG_SINGLE_INSTANCE |
	    TA_FLAG_MULTI_SESSION | TA_FLAG_SECURE_DATA_PATH |
	    TA_FLAG_INSTANCE_KEEP_ALIVE | TA_FLAG_CACHE_MAINTENANCE;
	struct ta_head *ta_head;
	struct user_ta_ctx *utc;
	struct user_ta_elf *exe;
	struct user_ta_elf *elf;
	uintptr_t vabase;
	TEE_Result res;

	/*
	 * Create context
	 */
	utc = calloc(1, sizeof(*utc));
	if (!utc) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);
	TAILQ_INIT(&utc->elfs);

	/*
	 * Create entry for the main executable
	 */
	exe = ta_elf(uuid, utc);
	if (!exe) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	exe->is_main = true;

	/*
	 * Prepare VA space for TA
	 */

	res = tee_mmu_init(utc);
	if (res)
		goto err;

	/* Temporary assignment to setup memory mapping */
	utc->ctx.flags = TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR;

	/*
	 * Load binaries and map them into the TA virtual memory. load_elf()
	 * may add external libraries to the list, so the loop will end when
	 * all the dependencies are satisfied or an error occurs.
	 * TODO: only the main executable is mapped currently
	 */
	TAILQ_FOREACH(elf, &utc->elfs, link) {
		res = load_elf(&elf->uuid, utc);
		if (res)
			goto err;
	}

	/*
	 * Perform relocations and apply final memory attributes
	 */
	TAILQ_FOREACH(elf, &utc->elfs, link) {

		/* FIXME */
		if (elf->is_main) {
			vabase = tee_mmu_get_load_addr(&utc->ctx);
		} else {
			vabase = (vaddr_t)mobj_get_va(elf->mobj_code, 0);
		}

		DMSG("Processing relocations in %pUl", (void *)&elf->uuid);
		res = elf_process_rel(elf->elf_state, vabase);
		if (res)
			goto err;

		res = load_elf_segments(utc, elf, false /* final attrs */);
		if (res)
			goto err;
	}

	utc->load_addr = tee_mmu_get_load_addr(&utc->ctx);
	ta_head = (struct ta_head *)(vaddr_t)utc->load_addr;

	if (memcmp(&ta_head->uuid, uuid, sizeof(TEE_UUID)) != 0) {
		res = TEE_ERROR_SECURITY;
		goto err;
	}

	/* check input flags bitmask consistency and save flags */
	if ((ta_head->flags & optional_flags) != ta_head->flags ||
	    (ta_head->flags & mandatory_flags) != mandatory_flags) {
		EMSG("TA flag issue: flags=%x optional=%x mandatory=%x",
		     ta_head->flags, optional_flags, mandatory_flags);
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	DMSG("ELF load address 0x%x", utc->load_addr);
	utc->ctx.ops = &user_ta_ops;
	utc->ctx.flags = ta_head->flags;
	utc->ctx.uuid = ta_head->uuid;
	utc->entry_func = ta_head->entry.ptr64;
	utc->ctx.ref_count = 1;
	condvar_init(&utc->ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->ctx, link);
	*ta_ctx = &utc->ctx;

	free_elf_states(utc);
	tee_mmu_set_ctx(NULL);
	return TEE_SUCCESS;
err:
	tee_mmu_set_ctx(NULL);
	if (utc) {
		pgt_flush_ctx(&utc->ctx);
		tee_pager_rem_uta_areas(utc);
		tee_mmu_final(utc);
		mobj_free(utc->mobj_stack);
		free_elf_states(utc);
		free_elfs(&utc->elfs);
		free(utc);
	}
	return res;
}

TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
			struct tee_ta_session *s)
{
	return ta_load(uuid, &s->ctx);
}
