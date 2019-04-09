// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2017 Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <ctype.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/user_ta.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <signed_hdr.h>
#include <stdio.h>
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

#include "elf_common.h"
#include "elf_load.h"
#include "elf_load_dyn.h"

struct load_seg {
	uint32_t flags;
	vaddr_t va;
	size_t size;
	struct mobj *mobj;
};

/* ELF file used by a TA (main executable or dynamic library) */
struct user_ta_elf {
	TEE_UUID uuid;
	struct elf_load_state *elf_state;
	vaddr_t load_addr;
	vaddr_t exidx_start; /* 32-bit ELF only */
	size_t exidx_size;
	struct load_seg *segs;
	size_t num_segs;
	struct file *file;

	TAILQ_ENTRY(user_ta_elf) link;
};

static void free_segs(struct load_seg *segs, size_t num_segs)
{
	size_t n = 0;

	for (n = 0; n < num_segs; n++)
		mobj_free(segs[n].mobj);
	free(segs);
}

static void free_elfs(struct user_ta_elf_head *elfs)
{
	struct user_ta_elf *elf;
	struct user_ta_elf *next;

	TAILQ_FOREACH_SAFE(elf, elfs, link, next) {
		TAILQ_REMOVE(elfs, elf, link);
		free_segs(elf->segs, elf->num_segs);
		file_put(elf->file);
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

static uint32_t elf_flags_to_mattr(uint32_t flags)
{
	uint32_t mattr = 0;

	if (flags & PF_X)
		mattr |= TEE_MATTR_UX;
	if (flags & PF_W)
		mattr |= TEE_MATTR_UW | TEE_MATTR_PW;
	if (flags & PF_R)
		mattr |= TEE_MATTR_UR | TEE_MATTR_PR;

	return mattr;
}

static TEE_Result get_elf_segments(struct user_ta_elf *elf,
				   struct load_seg **segs_ret,
				   size_t *num_segs_ret)
{
	struct elf_load_state *elf_state = elf->elf_state;
	TEE_Result res;
	size_t idx = 0;
	size_t num_segs = 0;
	struct load_seg *segs = NULL;

	/*
	 * Add code segment
	 */
	while (true) {
		vaddr_t va;
		size_t size;
		uint32_t flags;
		uint32_t type;

		res = elf_load_get_next_segment(elf_state, &idx, &va, &size,
						&flags, &type);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			break;
		if (res != TEE_SUCCESS)
			return res;

		if (type == PT_LOAD) {
			size_t oend = 0;
			void *p = realloc(segs, (num_segs + 1) * sizeof(*segs));

			if (!p) {
				free(segs);
				return TEE_ERROR_OUT_OF_MEMORY;
			}
			segs = p;
			segs[num_segs] = (struct load_seg) {
				.va = ROUNDDOWN(va, SMALL_PAGE_SIZE),
				.flags = flags,
			};
			oend = ROUNDUP(va + size, SMALL_PAGE_SIZE);
			segs[num_segs].size = oend - segs[num_segs].va;
			num_segs++;
		} else if (type == PT_ARM_EXIDX) {
			elf->exidx_start = va;
			elf->exidx_size = size;
		}
	}

	idx = 1;
	while (idx < num_segs) {
		if (core_is_buffer_intersect(segs[idx].va, segs[idx].size,
					     segs[idx - 1].va,
					     segs[idx - 1].size)) {
			size_t size = 0;

			/*
			 * All segments are supposed to be in order and if
			 * there's overlap it's only due to ROUNDUP() and
			 * ROUNDDOWN() above.
			 */
			assert(segs[idx - 1].va <= segs[idx].va);
			size = segs[idx].va + segs[idx].size - segs[idx - 1].va;
			assert(segs[idx - 1].size <= size);

			/* Merge the segments and their attributes */
			segs[idx - 1].size = size;
			segs[idx - 1].flags |= segs[idx].flags;

			/* Remove this index */
			memmove(segs + idx, segs + idx + 1,
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
	size_t num_pgs = ROUNDUP(size, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE;
	struct fobj *fobj = fobj_ta_mem_alloc(num_pgs);
	struct mobj *mobj = mobj_with_fobj_alloc(fobj);

	fobj_put(fobj);
	return mobj;
}

static TEE_Result find_ta_mem(struct file *file, unsigned int page_offset,
			      struct mobj **mobj)
{
	/*
	 * Note that we're not calling fobj_get() or fobj_put() directly in
	 * this function. Since file currently exists all its fobjs are
	 * also guaranteed to exist here.
	 *
	 * If mobj_with_fobj_alloc() succeeds it will call fobj_get()
	 * internally to guarantee that the fobj is available during the
	 * life time of the mobj.
	 */
	struct file_slice *fs = file_find_slice(file, page_offset);

	*mobj = NULL;
	/* Not finding a fobj is OK, the caller will allocate a new instead */
	if (!fs)
		return TEE_SUCCESS;
	/*
	 * If a fobj is found it has to match with the start or something is
	 * wrong, besides we wouldn't be able to map it properly either.
	 */
	assert(fs->page_offset == page_offset); /* in case we're debugging */
	if (fs->page_offset != page_offset)
		return TEE_ERROR_ITEM_NOT_FOUND;

	*mobj = mobj_with_fobj_alloc(fs->fobj);
	if (!*mobj)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
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
		DMSG("tee_user_ta_enter: TA panicked with code 0x%x",
		     utc->ctx.panic_code);
		serr = TEE_ORIGIN_TEE;
		res = TEE_ERROR_TARGET_DEAD;
	}

	/* Copy out value results */
	update_from_utee_param(param, usr_params);

	/*
	 * Clear out the parameter mappings added with tee_mmu_map_param()
	 * above.
	 */
	tee_mmu_clean_param(utc);

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

static int elf_idx(struct user_ta_ctx *utc, vaddr_t r_va, size_t r_size)
{
	struct user_ta_elf *elf;
	int idx = 0;

	TAILQ_FOREACH(elf, &utc->elfs, link) {
		size_t n;

		for (n = 0; n < elf->num_segs; n++)
			if (elf->segs[n].va == r_va &&
			    elf->segs[n].size == r_size)
				return idx;
		idx++;
	}
	return -1;
}

static void describe_region(struct user_ta_ctx *utc, vaddr_t va, size_t size,
			    char *desc, size_t desc_size)
{
	int idx;

	if (!desc_size)
		return;
	idx = elf_idx(utc, va, size);
	if (idx != -1)
		snprintf(desc, desc_size, "[%d]", idx);
	else
		desc[0] = '\0';
	desc[desc_size - 1] = '\0';
}

static void show_elfs(struct user_ta_ctx *utc)
{
	struct user_ta_elf *elf;
	size_t __maybe_unused idx = 0;

	TAILQ_FOREACH(elf, &utc->elfs, link)
		EMSG_RAW(" [%zu] %pUl @ 0x%0*" PRIxVA, idx++,
			 (void *)&elf->uuid, PRIxVA_WIDTH, elf->load_addr);
}

static void user_ta_dump_state(struct tee_ta_ctx *ctx)
{
	struct user_ta_ctx *utc = to_user_ta_ctx(ctx);
	struct vm_region *r;
	char flags[7] = { '\0', };
	char desc[13];
	size_t n = 0;

	EMSG_RAW(" arch: %s  load address: 0x%0*" PRIxVA " ctx-idr: %d",
		 utc->is_32bit ? "arm" : "aarch64", PRIxVA_WIDTH,
		 utc->load_addr, utc->vm_info->asid);
	EMSG_RAW(" stack: 0x%0*" PRIxVA " %zu",
		 PRIxVA_WIDTH, utc->stack_addr, utc->mobj_stack->size);
	TAILQ_FOREACH(r, &utc->vm_info->regions, link) {
		paddr_t pa = 0;

		if (r->mobj)
			mobj_get_pa(r->mobj, r->offset, 0, &pa);

		mattr_perm_to_str(flags, sizeof(flags), r->attr);
		describe_region(utc, r->va, r->size, desc, sizeof(desc));
		EMSG_RAW(" region %2zu: va 0x%0*" PRIxVA " pa 0x%0*" PRIxPA
			 " size 0x%06zx flags %s %s",
			 n, PRIxVA_WIDTH, r->va, PRIxPA_WIDTH, pa, r->size,
			 flags, desc);
		n++;
	}
	show_elfs(utc);
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

static void free_utc(struct user_ta_ctx *utc)
{
	struct user_ta_elf *elf = NULL;
	size_t n = 0;

	tee_pager_rem_uta_areas(utc);
	TAILQ_FOREACH(elf, &utc->elfs, link)
		for (n = 0; n < elf->num_segs; n++)
			release_ta_memory_by_mobj(elf->segs[n].mobj);
	release_ta_memory_by_mobj(utc->mobj_stack);
	release_ta_memory_by_mobj(utc->mobj_exidx);

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
	mobj_free(utc->mobj_stack);
	mobj_free(utc->mobj_exidx);
	free_elfs(&utc->elfs);

	/* Free cryp states created by this TA */
	tee_svc_cryp_free_states(utc);
	/* Close cryp objects opened by this TA */
	tee_obj_close_all(utc);
	/* Free emums created by this TA */
	tee_svc_storage_close_all_enum(utc);
	free(utc);
}

static void user_ta_ctx_destroy(struct tee_ta_ctx *ctx)
{
	free_utc(to_user_ta_ctx(ctx));
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

/*
 * Break unpaged attribute dependency propagation to user_ta_ops structure
 * content thanks to a runtime initialization of the ops reference.
 */
static struct tee_ta_ops const *_user_ta_ops;

static TEE_Result init_user_ta(void)
{
	_user_ta_ops = &user_ta_ops;

	return TEE_SUCCESS;
}
service_init(init_user_ta);

static void set_ta_ctx_ops(struct tee_ta_ctx *ctx)
{
	ctx->ops = _user_ta_ops;
}

bool is_user_ta_ctx(struct tee_ta_ctx *ctx)
{
	return ctx->ops == _user_ta_ops;
}

static TEE_Result check_ta_store(void)
{
	const struct user_ta_store_ops *op = NULL;

	SCATTERED_ARRAY_FOREACH(op, ta_stores, struct user_ta_store_ops)
		DMSG("TA store: \"%s\"", op->description);

	return TEE_SUCCESS;
}
service_init(check_ta_store);

#ifdef CFG_TA_DYNLINK

static int hex(char c)
{
	char lc = tolower(c);

	if (isdigit(lc))
		return lc - '0';
	if (isxdigit(lc))
		return lc - 'a' + 10;
	return -1;
}

static uint32_t parse_hex(const char *s, size_t nchars, uint32_t *res)
{
	uint32_t v = 0;
	size_t n;
	int c;

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

static TEE_Result add_elf_deps(struct user_ta_ctx *utc, char **deps,
			       size_t num_deps)
{
	struct user_ta_elf *libelf;
	TEE_Result res = TEE_SUCCESS;
	TEE_UUID u;
	size_t n;

	for (n = 0; n < num_deps; n++) {
		res = parse_uuid(deps[n], &u);
		if (res) {
			EMSG("Invalid dependency (not a UUID): %s", deps[n]);
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
		*val += elf->load_addr;
		FMSG("%pUl/0x%" PRIxPTR " %s", (void *)&elf->uuid, *val, name);
		return TEE_SUCCESS;
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result add_deps(struct user_ta_ctx *utc,
			   struct elf_load_state *state, vaddr_t load_addr)
{
	char **deps = NULL;
	size_t num_deps = 0;
	TEE_Result res;

	res = elf_get_needed(state, load_addr, &deps, &num_deps);
	if (res)
		return res;

	res = add_elf_deps(utc, deps, num_deps);
	free(deps);

	return res;
}

#else

static TEE_Result (*resolve_symbol)(struct user_ta_elf_head *, const char *,
				    uintptr_t *);

static TEE_Result add_deps(struct user_ta_ctx *utc __unused,
			   struct elf_load_state *state __unused,
			   vaddr_t load_addr __unused)
{
	return TEE_SUCCESS;
}

#endif

static TEE_Result register_ro_slices(struct file **file,
				     const struct user_ta_store_ops *ta_store,
				     struct user_ta_store_handle *handle,
				     struct load_seg *segs, size_t num_segs)
{
	TEE_Result res = TEE_SUCCESS;
	struct file *f = NULL;
	struct file_slice *fs = NULL;
	size_t num_slices = 0;
	size_t n = 0;
	uint8_t tag[FILE_TAG_SIZE] = { 0 };
	unsigned int tag_len = sizeof(tag);

	assert(!*file);

	res = ta_store->get_tag(handle, tag, &tag_len);
	if (res)
		return res;

	for (n = 0; n < num_segs; n++)
		if (!(segs[n].flags & PF_W))
			num_slices++;

	fs = calloc(num_slices, sizeof(*fs));
	if (!fs)
		return TEE_ERROR_OUT_OF_MEMORY;

	num_slices = 0;
	for (n = 0; n < num_segs; n++) {
		if (!(segs[n].flags & PF_W)) {
			fs[num_slices].fobj = mobj_get_fobj(segs[n].mobj);
			fs[num_slices].page_offset = (segs[n].va - segs[0].va) /
						     SMALL_PAGE_SIZE;
			/*
			 * The fobjs is guaranteed to exist now, and
			 * file_new() will call fobj_get() on all supplied
			 * fobjs later.
			 */
			fobj_put(fs[num_slices].fobj);
			num_slices++;
		}
	}

	f = file_new(tag, tag_len, fs, num_slices);
	free(fs);
	if (!f)
		return TEE_ERROR_OUT_OF_MEMORY;

	*file = f;
	return TEE_SUCCESS;
}

#ifdef CFG_TA_ASLR
static size_t aslr_offset(size_t min, size_t max)
{
	uint32_t rnd32 = 0;
	size_t rnd = 0;

	assert(min <= max);
	if (max > min) {
		if (crypto_rng_read(&rnd32, sizeof(rnd32))) {
			DMSG("Random read failed");
			return min;
		}
		rnd = rnd32 % (max - min);
	}
	return (min + rnd) * CORE_MMU_USER_CODE_SIZE;
}

static vaddr_t get_stack_va_hint(struct user_ta_ctx *utc)
{
	struct vm_region *r = NULL;
	vaddr_t base = 0;

	r = TAILQ_LAST(&utc->vm_info->regions, vm_region_head);
	if (r) {
		/*
		 * Adding an empty page to separate TA mappings from already
		 * present mappings with TEE_MATTR_PERMANENT to satisfy
		 * select_va_in_range()
		 */
		base = r->va + r->size + CORE_MMU_USER_CODE_SIZE;
	} else {
		core_mmu_get_user_va_range(&base, NULL);
	}

	return base + aslr_offset(CFG_TA_ASLR_MIN_OFFSET_PAGES,
				  CFG_TA_ASLR_MAX_OFFSET_PAGES);
}
#else
static vaddr_t get_stack_va_hint(struct user_ta_ctx *utc __unused)
{
	return 0;
}
#endif

static TEE_Result load_elf_from_store(const TEE_UUID *uuid,
				      const struct user_ta_store_ops *ta_store,
				      struct user_ta_ctx *utc)
{
	struct user_ta_store_handle *handle = NULL;
	struct elf_load_state *elf_state = NULL;
	struct file *file = NULL;
	struct ta_head *ta_head;
	struct user_ta_elf *exe;
	struct user_ta_elf *elf;
	struct user_ta_elf *prev;
	TEE_Result res;
	size_t vasize;
	void *p;
	size_t n;
	size_t num_segs = 0;
	struct load_seg *segs = NULL;
	unsigned int next_page_offset = 0;

	res = ta_store->open(uuid, &handle);
	if (res)
		return res;

	elf = ta_elf(uuid, utc);
	if (!elf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	exe = TAILQ_FIRST(&utc->elfs);
	prev = TAILQ_PREV(elf, user_ta_elf_head, link);

	res = elf_load_init(ta_store, handle, elf == exe, &utc->elfs,
			    resolve_symbol, &elf_state);
	if (res)
		goto out;
	elf->elf_state = elf_state;

	res = elf_load_head(elf_state,
			    elf == exe ? sizeof(struct ta_head) : 0,
			    &p, &vasize, &utc->is_32bit,
			    elf == exe ? &utc->entry_func : NULL);
	if (res)
		goto out;
	ta_head = p;
	if (ta_head->depr_entry != UINT64_MAX) {
		DMSG("Using decprecated TA entry via ta_head");
		utc->entry_func = ta_head->depr_entry;
	} else {
		file = elf_load_get_file(elf_state);
	}

	if (elf == exe) {
		/* Ensure proper alignment of stack */
		size_t stack_sz = ROUNDUP(ta_head->stack_size,
					  STACK_ALIGNMENT);

		if (!stack_sz) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
		utc->mobj_stack = alloc_ta_mem(stack_sz);
		if (!utc->mobj_stack) {
			res = TEE_ERROR_OUT_OF_MEMORY;
			goto out;
		}
	}

	/*
	 * Map physical memory into TA virtual memory
	 */
	if (elf == exe) {
		res = vm_info_init(utc);
		if (res != TEE_SUCCESS)
			goto out;

		utc->stack_addr = get_stack_va_hint(utc);
		res = vm_map(utc, &utc->stack_addr, utc->mobj_stack->size,
			     TEE_MATTR_URW | TEE_MATTR_PRW, utc->mobj_stack,
			     0);
		if (res)
			goto out;
	}

	res = get_elf_segments(elf, &segs, &num_segs);
	if (res != TEE_SUCCESS)
		goto out;

	if (prev)
		elf->load_addr = prev->segs[prev->num_segs - 1].va +
				 prev->segs[prev->num_segs - 1].size;
	else
		elf->load_addr = utc->stack_addr + utc->mobj_stack->size;
	elf->load_addr = ROUNDUP(elf->load_addr, CORE_MMU_USER_CODE_SIZE);

	for (n = 0; n < num_segs; n++) {
		uint32_t prot = elf_flags_to_mattr(segs[n].flags);
		size_t end_va = 0;

		/*
		 * The first segment has va == 0 and if elf->load_addr
		 * hasn't been initialized yet it will be 0 too. This
		 * results in va still 0 and thus will be chosen by
		 * vm_map().
		 */
		segs[n].va += elf->load_addr;
		if (file) {
			res = find_ta_mem(file, next_page_offset,
					  &segs[n].mobj);
			if (res)
				goto out;
			/*
			 * Note that segs[n].mobj can still be NULL if
			 * corresponding fobj isn't found.
			 */
		}
		if (!segs[n].mobj) {
			segs[n].mobj = alloc_ta_mem(segs[n].size);
			if (!segs[n].mobj) {
				res = TEE_ERROR_OUT_OF_MEMORY;
				goto out;
			}
			prot |= TEE_MATTR_PRW;
		}
		res = vm_map(utc, &segs[n].va, segs[n].size, prot,
			     segs[n].mobj, 0);
		if (res)
			goto out;
		if (!n) {
			elf->load_addr = segs[0].va;
			DMSG("ELF load address %#" PRIxVA, elf->load_addr);
		}

		if (ADD_OVERFLOW(segs[n].va, segs[n].size, &end_va) ||
		    end_va < elf->load_addr)
			panic();
		next_page_offset = (end_va - elf->load_addr) / SMALL_PAGE_SIZE;
	}

	tee_mmu_set_ctx(&utc->ctx);

	res = elf_load_body(elf_state, elf->load_addr);
	if (res)
		goto out;

	/*
	 * Legacy TAs can't share read-only memory due to the way
	 * relocation is updated.
	 */
	if (!file && ta_head->depr_entry == UINT64_MAX) {
		res = register_ro_slices(&file, ta_store, handle,
					 segs, num_segs);
		if (res)
			goto out;
	}

	/* Find any external dependency (dynamically linked libraries) */
	res = add_deps(utc, elf_state, elf->load_addr);
out:
	if (res) {
		file_put(file);
		free_segs(segs, num_segs);
	} else {
		elf->file = file;
		elf->segs = segs;
		elf->num_segs = num_segs;
	}
	ta_store->close(handle);
	/* utc is cleaned by caller on error */
	return res;
}

/* Loads a single ELF file (main executable or library) */
static TEE_Result load_elf(const TEE_UUID *uuid, struct user_ta_ctx *utc)
{
	TEE_Result res;
	const struct user_ta_store_ops *op = NULL;

	SCATTERED_ARRAY_FOREACH(op, ta_stores, struct user_ta_store_ops) {
		DMSG("Lookup user TA ELF %pUl (%s)", (void *)uuid,
		     op->description);

		res = load_elf_from_store(uuid, op, utc);
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			continue;
		if (res) {
			DMSG("res=0x%x", res);
			continue;
		}

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

static TEE_Result set_seg_prot(struct user_ta_ctx *utc,
			       struct user_ta_elf *elf)
{
	TEE_Result res;
	size_t n;

	for (n = 0; n < elf->num_segs; n++) {
		struct load_seg *seg = &elf->segs[n];

		res = vm_set_prot(utc, seg->va, seg->size,
				  elf_flags_to_mattr(seg->flags));
		if (res)
			break;
	}
	return res;
}

#ifdef CFG_UNWIND

/*
 * 32-bit TAs: set the address and size of the exception index table (EXIDX).
 * If the TA contains only one ELF, we point to its table. Otherwise, a
 * consolidated table is made by concatenating the tables found in each ELF and
 * adjusting their content to account for the offset relative to the original
 * location.
 */
static TEE_Result set_exidx(struct user_ta_ctx *utc)
{
	struct user_ta_elf *exe;
	struct user_ta_elf *elf;
	struct user_ta_elf *last_elf;
	vaddr_t exidx;
	size_t exidx_sz = 0;
	TEE_Result res;
	uint8_t *p;

	if (!utc->is_32bit)
		return TEE_SUCCESS;

	exe = TAILQ_FIRST(&utc->elfs);
	if (!TAILQ_NEXT(exe, link)) {
		/* We have a single ELF: simply reference its table */
		utc->exidx_start = exe->exidx_start;
		utc->exidx_size = exe->exidx_size;
		return TEE_SUCCESS;
	}
	last_elf = TAILQ_LAST(&utc->elfs, user_ta_elf_head);

	TAILQ_FOREACH(elf, &utc->elfs, link)
		exidx_sz += elf->exidx_size;

	if (!exidx_sz) {
		/* The empty table from first segment will fit */
		utc->exidx_start = exe->exidx_start;
		utc->exidx_size = exe->exidx_size;
		return TEE_SUCCESS;
	}

	utc->mobj_exidx = alloc_ta_mem(exidx_sz);
	if (!utc->mobj_exidx)
		return TEE_ERROR_OUT_OF_MEMORY;
	exidx = ROUNDUP(last_elf->segs[last_elf->num_segs - 1].va +
				last_elf->segs[last_elf->num_segs - 1].size,
			CORE_MMU_USER_CODE_SIZE);
	res = vm_map(utc, &exidx, exidx_sz, TEE_MATTR_UR | TEE_MATTR_PRW,
		     utc->mobj_exidx, 0);
	if (res)
		goto err;
	DMSG("New EXIDX table mapped at 0x%" PRIxVA " size %zu",
	     exidx, exidx_sz);

	p = (void *)exidx;
	TAILQ_FOREACH(elf, &utc->elfs, link) {
		void *e_exidx = (void *)(elf->exidx_start + elf->load_addr);
		size_t e_exidx_sz = elf->exidx_size;
		int32_t offs = (int32_t)((vaddr_t)e_exidx - (vaddr_t)p);

		memcpy(p, e_exidx, e_exidx_sz);
		res = relocate_exidx(p, e_exidx_sz, offs);
		if (res)
			goto err;
		p += e_exidx_sz;
	}

	/*
	 * Drop privileged mode permissions. Normally we should keep
	 * TEE_MATTR_PR because the code that accesses this table runs in
	 * privileged mode. However, privileged read is always enabled if
	 * unprivileged read is enabled, so it doesn't matter. For consistency
	 * with other ELF section mappings, let's clear all the privileged
	 * permission bits.
	 */
	res = vm_set_prot(utc, exidx,
			  ROUNDUP(exidx_sz, SMALL_PAGE_SIZE),
			  TEE_MATTR_UR);
	if (res)
		goto err;

	utc->exidx_start = exidx - utc->load_addr;
	utc->exidx_size = exidx_sz;

	return TEE_SUCCESS;
err:
	mobj_free(utc->mobj_exidx);
	utc->mobj_exidx = NULL;
	return res;
}

#else /* CFG_UNWIND */

static TEE_Result set_exidx(struct user_ta_ctx *utc __unused)
{
	return TEE_SUCCESS;
}

#endif /* CFG_UNWIND */

TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
				       struct tee_ta_session *s)
{
	TEE_Result res;
	struct user_ta_ctx *utc = NULL;
	struct ta_head *ta_head;
	struct user_ta_elf *exe;
	struct user_ta_elf *elf;

	/* Register context */
	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc)
		return TEE_ERROR_OUT_OF_MEMORY;

	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);
	TAILQ_INIT(&utc->elfs);

	/*
	 * Set context TA operation structure. It is required by generic
	 * implementation to identify userland TA versus pseudo TA contexts.
	 */
	set_ta_ctx_ops(&utc->ctx);

	/*
	 * Create entry for the main executable
	 */
	exe = ta_elf(uuid, utc);
	if (!exe) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	/*
	 * Load binaries and map them into the TA virtual memory. load_elf()
	 * may add external libraries to the list, so the loop will end when
	 * all the dependencies are satisfied or an error occurs.
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
		DMSG("Processing relocations in %pUl", (void *)&elf->uuid);
		res = elf_process_rel(elf->elf_state, elf->load_addr);
		if (res)
			goto err;
		res = set_seg_prot(utc, elf);
		if (res)
			goto err;
	}

	utc->load_addr = exe->load_addr;
	res = set_exidx(utc);
	if (res)
		goto err;

	ta_head = (struct ta_head *)(vaddr_t)utc->load_addr;

	if (memcmp(&ta_head->uuid, uuid, sizeof(TEE_UUID)) != 0) {
		res = TEE_ERROR_SECURITY;
		goto err;
	}

	if (ta_head->flags & ~TA_FLAGS_MASK) {
		EMSG("Invalid TA flag(s) 0x%" PRIx32,
			ta_head->flags & ~TA_FLAGS_MASK);
		res = TEE_ERROR_BAD_FORMAT;
		goto err;
	}

	utc->ctx.flags = ta_head->flags;
	utc->ctx.uuid = ta_head->uuid;
	utc->entry_func += utc->load_addr;
	utc->ctx.ref_count = 1;
	condvar_init(&utc->ctx.busy_cv);
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->ctx, link);
	s->ctx = &utc->ctx;

	free_elf_states(utc);
	tee_mmu_set_ctx(NULL);
	return TEE_SUCCESS;

err:
	free_elf_states(utc);
	tee_mmu_set_ctx(NULL);
	free_utc(utc);
	return res;
}
