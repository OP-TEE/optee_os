// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2020 Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <ctype.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/linker.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/user_access.h>
#include <kernel/user_mode_ctx.h>
#include <kernel/user_ta.h>
#include <kernel/user_ta_store.h>
#include <ldelf.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/file.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/pgt_cache.h>
#include <mm/tee_mm.h>
#include <mm/tee_mmu.h>
#include <mm/tee_pager.h>
#include <optee_rpc_cmd.h>
#include <printk.h>
#include <signed_hdr.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <ta_pub_key.h>
#include <tee/arch_svc.h>
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

extern uint8_t ldelf_data[];
extern const unsigned int ldelf_code_size;
extern const unsigned int ldelf_data_size;
extern const unsigned int ldelf_entry;
#ifdef ARM32
const bool is_arm32 = true;
#else
const bool is_arm32;
#endif

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
	thread_user_clear_vfp(&utc->uctx.vfp);
#endif
}

static bool inc_recursion(void)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	if (tsd->syscall_recursion >= CFG_CORE_MAX_SYSCALL_RECURSION) {
		DMSG("Maximum allowed recursion depth reached (%u)",
		     CFG_CORE_MAX_SYSCALL_RECURSION);
		return false;
	}

	tsd->syscall_recursion++;
	return true;
}

static void dec_recursion(void)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	assert(tsd->syscall_recursion);
	tsd->syscall_recursion--;
}

static TEE_Result user_ta_enter(struct ts_session *session,
				enum utee_entry_func func, uint32_t cmd)
{
	TEE_Result res = TEE_SUCCESS;
	struct utee_params *usr_params = NULL;
	uaddr_t usr_stack = 0;
	struct user_ta_ctx *utc = to_user_ta_ctx(session->ctx);
	struct tee_ta_session *ta_sess = to_ta_session(session);
	struct ts_session *ts_sess __maybe_unused = NULL;
	void *param_va[TEE_NUM_PARAMS] = { NULL };

	if (!inc_recursion()) {
		/* Using this error code since we've run out of resources. */
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out_clr_cancel;
	}
	if (ta_sess->param) {
		/* Map user space memory */
		res = tee_mmu_map_param(&utc->uctx, ta_sess->param, param_va);
		if (res != TEE_SUCCESS)
			goto out;
	}

	/* Switch to user ctx */
	ts_push_current_session(session);

	/* Make room for usr_params at top of stack */
	usr_stack = utc->stack_ptr;
	usr_stack -= ROUNDUP(sizeof(struct utee_params), STACK_ALIGNMENT);
	usr_params = (struct utee_params *)usr_stack;
	if (ta_sess->param)
		init_utee_param(usr_params, ta_sess->param, param_va);
	else
		memset(usr_params, 0, sizeof(*usr_params));

	res = thread_enter_user_mode(func, kaddr_to_uref(session),
				     (vaddr_t)usr_params, cmd, usr_stack,
				     utc->entry_func, utc->is_32bit,
				     &utc->ta_ctx.panicked,
				     &utc->ta_ctx.panic_code);

	clear_vfp_state(utc);

	if (utc->ta_ctx.panicked) {
		abort_print_current_ta();
		DMSG("tee_user_ta_enter: TA panicked with code 0x%x",
		     utc->ta_ctx.panic_code);
		res = TEE_ERROR_TARGET_DEAD;
	} else {
		/*
		 * According to GP spec the origin should allways be set to
		 * the TA after TA execution
		 */
		ta_sess->err_origin = TEE_ORIGIN_TRUSTED_APP;
	}

	if (ta_sess->param) {
		/* Copy out value results */
		update_from_utee_param(ta_sess->param, usr_params);

		/*
		 * Clear out the parameter mappings added with
		 * tee_mmu_map_param() above.
		 */
		tee_mmu_clean_param(&utc->uctx);
	}


	ts_sess = ts_pop_current_session();
	assert(ts_sess == session);

out:
	dec_recursion();
out_clr_cancel:
	/*
	 * Clear the cancel state now that the user TA has returned. The next
	 * time the TA will be invoked will be with a new operation and should
	 * not have an old cancellation pending.
	 */
	ta_sess->cancel = false;

	return res;
}

static TEE_Result init_with_ldelf(struct ts_session *sess __maybe_unused,
				  struct user_ta_ctx *utc)
{
	TEE_Result res = TEE_SUCCESS;
	struct ldelf_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	uaddr_t usr_stack = 0;

	usr_stack = utc->ldelf_stack_ptr;
	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	arg = (struct ldelf_arg *)usr_stack;
	memset(arg, 0, sizeof(*arg));
	arg->uuid = utc->ta_ctx.ts_ctx.uuid;

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, utc->entry_func,
				     is_arm32, &panicked, &panic_code);

	clear_vfp_state(utc);
	if (panicked) {
		abort_print_current_ta();
		EMSG("ldelf panicked");
		return TEE_ERROR_GENERIC;
	}
	if (res) {
		EMSG("ldelf failed with res: %#"PRIx32, res);
		return res;
	}

	res = tee_mmu_check_access_rights(&utc->uctx, TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (uaddr_t)arg, sizeof(*arg));
	if (res)
		return res;

	/*
	 * This is already checked by the elf loader, but since it runs in
	 * user mode we're not trusting it entirely.
	 */
	if (arg->flags & ~TA_FLAGS_MASK)
		return TEE_ERROR_BAD_FORMAT;

	utc->is_32bit = arg->is_32bit;
	utc->entry_func = arg->entry_func;
	utc->stack_ptr = arg->stack_ptr;
	utc->ta_ctx.flags = arg->flags;
	utc->dump_entry_func = arg->dump_entry;
#ifdef CFG_FTRACE_SUPPORT
	utc->ftrace_entry_func = arg->ftrace_entry;
	sess->fbuf = arg->fbuf;
#endif
	utc->dl_entry_func = arg->dl_entry;

	return TEE_SUCCESS;
}

static TEE_Result user_ta_enter_open_session(struct ts_session *s)
{
	return user_ta_enter(s, UTEE_ENTRY_FUNC_OPEN_SESSION, 0);
}

static TEE_Result user_ta_enter_invoke_cmd(struct ts_session *s, uint32_t cmd)
{
	return user_ta_enter(s, UTEE_ENTRY_FUNC_INVOKE_COMMAND, cmd);
}

static void user_ta_enter_close_session(struct ts_session *s)
{
	/* Only if the TA was fully initialized by ldelf */
	if (!to_user_ta_ctx(s->ctx)->is_initializing)
		user_ta_enter(s, UTEE_ENTRY_FUNC_CLOSE_SESSION, 0);
}

static void dump_state_no_ldelf_dbg(struct user_ta_ctx *utc)
{
	user_mode_ctx_print_mappings(&utc->uctx);
}

static TEE_Result dump_state_ldelf_dbg(struct user_ta_ctx *utc)
{
	TEE_Result res = TEE_SUCCESS;
	uaddr_t usr_stack = utc->ldelf_stack_ptr;
	struct dump_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	struct thread_specific_data *tsd = thread_get_tsd();
	struct vm_region *r = NULL;
	size_t n = 0;

	TAILQ_FOREACH(r, &utc->uctx.vm_info.regions, link)
		if (r->attr & TEE_MATTR_URWX)
			n++;

	usr_stack = utc->ldelf_stack_ptr;
	usr_stack -= ROUNDUP(sizeof(*arg) + n * sizeof(struct dump_map),
			     STACK_ALIGNMENT);
	arg = (struct dump_entry_arg *)usr_stack;

	res = tee_mmu_check_access_rights(&utc->uctx, TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (uaddr_t)arg, sizeof(*arg));
	if (res) {
		EMSG("ldelf stack is inaccessible!");
		return res;
	}

	memset(arg, 0, sizeof(*arg) + n * sizeof(struct dump_map));

	arg->num_maps = n;
	n = 0;
	TAILQ_FOREACH(r, &utc->uctx.vm_info.regions, link) {
		if (r->attr & TEE_MATTR_URWX) {
			if (r->mobj)
				mobj_get_pa(r->mobj, r->offset, 0,
					    &arg->maps[n].pa);
			arg->maps[n].va = r->va;
			arg->maps[n].sz = r->size;
			if (r->attr & TEE_MATTR_UR)
				arg->maps[n].flags |= DUMP_MAP_READ;
			if (r->attr & TEE_MATTR_UW)
				arg->maps[n].flags |= DUMP_MAP_WRITE;
			if (r->attr & TEE_MATTR_UX)
				arg->maps[n].flags |= DUMP_MAP_EXEC;
			if (r->attr & TEE_MATTR_SECURE)
				arg->maps[n].flags |= DUMP_MAP_SECURE;
			if (r->flags & VM_FLAG_EPHEMERAL)
				arg->maps[n].flags |= DUMP_MAP_EPHEM;
			if (r->flags & VM_FLAG_LDELF)
				arg->maps[n].flags |= DUMP_MAP_LDELF;
			n++;
		}
	}

	arg->is_arm32 = utc->is_32bit;
#ifdef ARM32
		arg->arm32.regs[0] = tsd->abort_regs.r0;
		arg->arm32.regs[1] = tsd->abort_regs.r1;
		arg->arm32.regs[2] = tsd->abort_regs.r2;
		arg->arm32.regs[3] = tsd->abort_regs.r3;
		arg->arm32.regs[4] = tsd->abort_regs.r4;
		arg->arm32.regs[5] = tsd->abort_regs.r5;
		arg->arm32.regs[6] = tsd->abort_regs.r6;
		arg->arm32.regs[7] = tsd->abort_regs.r7;
		arg->arm32.regs[8] = tsd->abort_regs.r8;
		arg->arm32.regs[9] = tsd->abort_regs.r9;
		arg->arm32.regs[10] = tsd->abort_regs.r10;
		arg->arm32.regs[11] = tsd->abort_regs.r11;
		arg->arm32.regs[12] = tsd->abort_regs.ip;
		arg->arm32.regs[13] = tsd->abort_regs.usr_sp; /*SP*/
		arg->arm32.regs[14] = tsd->abort_regs.usr_lr; /*LR*/
		arg->arm32.regs[15] = tsd->abort_regs.elr; /*PC*/
#endif /*ARM32*/
#ifdef ARM64
	if (utc->is_32bit) {
		arg->arm32.regs[0] = tsd->abort_regs.x0;
		arg->arm32.regs[1] = tsd->abort_regs.x1;
		arg->arm32.regs[2] = tsd->abort_regs.x2;
		arg->arm32.regs[3] = tsd->abort_regs.x3;
		arg->arm32.regs[4] = tsd->abort_regs.x4;
		arg->arm32.regs[5] = tsd->abort_regs.x5;
		arg->arm32.regs[6] = tsd->abort_regs.x6;
		arg->arm32.regs[7] = tsd->abort_regs.x7;
		arg->arm32.regs[8] = tsd->abort_regs.x8;
		arg->arm32.regs[9] = tsd->abort_regs.x9;
		arg->arm32.regs[10] = tsd->abort_regs.x10;
		arg->arm32.regs[11] = tsd->abort_regs.x11;
		arg->arm32.regs[12] = tsd->abort_regs.x12;
		arg->arm32.regs[13] = tsd->abort_regs.x13; /*SP*/
		arg->arm32.regs[14] = tsd->abort_regs.x14; /*LR*/
		arg->arm32.regs[15] = tsd->abort_regs.elr; /*PC*/
	} else {
		arg->arm64.fp = tsd->abort_regs.x29;
		arg->arm64.pc = tsd->abort_regs.elr;
		arg->arm64.sp = tsd->abort_regs.sp_el0;
	}
#endif /*ARM64*/

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, utc->dump_entry_func,
				     is_arm32, &panicked, &panic_code);
	clear_vfp_state(utc);
	if (panicked) {
		utc->dump_entry_func = 0;
		EMSG("ldelf dump function panicked");
		abort_print_current_ta();
		res = TEE_ERROR_TARGET_DEAD;
	}

	return res;
}

static void user_ta_dump_state(struct ts_ctx *ctx)
{
	struct user_ta_ctx *utc = to_user_ta_ctx(ctx);

	if (utc->dump_entry_func) {
		TEE_Result res = dump_state_ldelf_dbg(utc);

		if (!res || res == TEE_ERROR_TARGET_DEAD)
			return;
		/*
		 * Fall back to dump_state_no_ldelf_dbg() if
		 * dump_state_ldelf_dbg() fails for some reason.
		 *
		 * If dump_state_ldelf_dbg() failed with panic
		 * where done since abort_print_current_ta() will be
		 * called which will dump the memory map.
		 */
	}

	dump_state_no_ldelf_dbg(utc);
}

#ifdef CFG_FTRACE_SUPPORT
static TEE_Result dump_ftrace(struct user_ta_ctx *utc, void *buf, size_t *blen)
{
	uaddr_t usr_stack = utc->ldelf_stack_ptr;
	TEE_Result res = TEE_SUCCESS;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	size_t *arg = NULL;

	if (!utc->ftrace_entry_func)
		return TEE_ERROR_NOT_SUPPORTED;

	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	arg = (size_t *)usr_stack;

	res = tee_mmu_check_access_rights(&utc->uctx, TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (uaddr_t)arg, sizeof(*arg));
	if (res) {
		EMSG("ldelf stack is inaccessible!");
		return res;
	}

	*arg = *blen;

	res = thread_enter_user_mode((vaddr_t)buf, (vaddr_t)arg, 0, 0,
				     usr_stack, utc->ftrace_entry_func,
				     is_arm32, &panicked, &panic_code);
	clear_vfp_state(utc);
	if (panicked) {
		utc->ftrace_entry_func = 0;
		EMSG("ldelf ftrace function panicked");
		abort_print_current_ta();
		res = TEE_ERROR_TARGET_DEAD;
	}

	if (!res) {
		if (*arg > *blen)
			res = TEE_ERROR_SHORT_BUFFER;
		*blen = *arg;
	}

	return res;
}

static void user_ta_dump_ftrace(struct ts_ctx *ctx)
{
	uint32_t prot = TEE_MATTR_URW;
	struct user_ta_ctx *utc = to_user_ta_ctx(ctx);
	struct thread_param params[3] = { };
	TEE_Result res = TEE_SUCCESS;
	struct mobj *mobj = NULL;
	uint8_t *ubuf = NULL;
	void *buf = NULL;
	size_t pl_sz = 0;
	size_t blen = 0, ld_addr_len = 0;
	vaddr_t va = 0;

	res = dump_ftrace(utc, NULL, &blen);
	if (res != TEE_ERROR_SHORT_BUFFER)
		return;

#define LOAD_ADDR_DUMP_SIZE	64
	pl_sz = ROUNDUP(blen + sizeof(TEE_UUID) + LOAD_ADDR_DUMP_SIZE,
			SMALL_PAGE_SIZE);

	mobj = thread_rpc_alloc_payload(pl_sz);
	if (!mobj) {
		EMSG("Ftrace thread_rpc_alloc_payload failed");
		return;
	}

	buf = mobj_get_va(mobj, 0);
	if (!buf)
		goto out_free_pl;

	res = vm_map(&utc->uctx, &va, mobj->size, prot, VM_FLAG_EPHEMERAL,
		     mobj, 0);
	if (res)
		goto out_free_pl;

	ubuf = (uint8_t *)va + mobj_get_phys_offs(mobj, mobj->phys_granule);
	memcpy(ubuf, &ctx->uuid, sizeof(TEE_UUID));
	ubuf += sizeof(TEE_UUID);

	ld_addr_len = snprintk((char *)ubuf, LOAD_ADDR_DUMP_SIZE,
			       "TEE load address @ %#"PRIxVA"\n",
			       VCORE_START_VA);
	ubuf += ld_addr_len;

	res = dump_ftrace(utc, ubuf, &blen);
	if (res) {
		EMSG("Ftrace dump failed: %#"PRIx32, res);
		goto out_unmap_pl;
	}

	params[0] = THREAD_PARAM_VALUE(INOUT, 0, 0, 0);
	params[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, sizeof(TEE_UUID));
	params[2] = THREAD_PARAM_MEMREF(IN, mobj, sizeof(TEE_UUID),
					blen + ld_addr_len);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_FTRACE, 3, params);
	if (res)
		EMSG("Ftrace thread_rpc_cmd res: %#"PRIx32, res);

out_unmap_pl:
	res = vm_unmap(&utc->uctx, va, mobj->size);
	assert(!res);
out_free_pl:
	thread_rpc_free_payload(mobj);
}
#endif /*CFG_FTRACE_SUPPORT*/

#ifdef CFG_TA_GPROF_SUPPORT
static void user_ta_gprof_set_status(enum ts_gprof_status status)
{
	if (status == TS_GPROF_SUSPEND)
		tee_ta_update_session_utime_suspend();
	else
		tee_ta_update_session_utime_resume();
}
#endif /*CFG_TA_GPROF_SUPPORT*/

static void free_utc(struct user_ta_ctx *utc)
{
	tee_pager_rem_um_areas(&utc->uctx);

	/*
	 * Close sessions opened by this TA
	 * Note that tee_ta_close_session() removes the item
	 * from the utc->open_sessions list.
	 */
	while (!TAILQ_EMPTY(&utc->open_sessions)) {
		tee_ta_close_session(TAILQ_FIRST(&utc->open_sessions),
				     &utc->open_sessions, KERN_IDENTITY);
	}

	vm_info_final(&utc->uctx);

	/* Free cryp states created by this TA */
	tee_svc_cryp_free_states(utc);
	/* Close cryp objects opened by this TA */
	tee_obj_close_all(utc);
	/* Free emums created by this TA */
	tee_svc_storage_close_all_enum(utc);
	free(utc);
}

static void user_ta_ctx_destroy(struct ts_ctx *ctx)
{
	free_utc(to_user_ta_ctx(ctx));
}

static uint32_t user_ta_get_instance_id(struct ts_ctx *ctx)
{
	return to_user_ta_ctx(ctx)->uctx.vm_info.asid;
}

static const struct ts_ops user_ta_ops __rodata_unpaged = {
	.enter_open_session = user_ta_enter_open_session,
	.enter_invoke_cmd = user_ta_enter_invoke_cmd,
	.enter_close_session = user_ta_enter_close_session,
	.dump_state = user_ta_dump_state,
#ifdef CFG_FTRACE_SUPPORT
	.dump_ftrace = user_ta_dump_ftrace,
#endif
	.destroy = user_ta_ctx_destroy,
	.get_instance_id = user_ta_get_instance_id,
	.handle_svc = user_ta_handle_svc,
#ifdef CFG_TA_GPROF_SUPPORT
	.gprof_set_status = user_ta_gprof_set_status,
#endif
};

/*
 * Break unpaged attribute dependency propagation to user_ta_ops structure
 * content thanks to a runtime initialization of the ops reference.
 */
static const struct ts_ops *_user_ta_ops;

static TEE_Result init_user_ta(void)
{
	_user_ta_ops = &user_ta_ops;

	return TEE_SUCCESS;
}
service_init(init_user_ta);

static void set_ta_ctx_ops(struct tee_ta_ctx *ctx)
{
	ctx->ts_ctx.ops = _user_ta_ops;
}

bool is_user_ta_ctx(struct ts_ctx *ctx)
{
	return ctx && ctx->ops == _user_ta_ops;
}

static TEE_Result check_ta_store(void)
{
	const struct user_ta_store_ops *op = NULL;

	SCATTERED_ARRAY_FOREACH(op, ta_stores, struct user_ta_store_ops)
		DMSG("TA store: \"%s\"", op->description);

	return TEE_SUCCESS;
}
service_init(check_ta_store);

static TEE_Result alloc_and_map_ldelf_fobj(struct user_ta_ctx *utc, size_t sz,
					   uint32_t prot, vaddr_t *va)
{
	size_t num_pgs = ROUNDUP(sz, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE;
	struct fobj *fobj = fobj_ta_mem_alloc(num_pgs);
	struct mobj *mobj = mobj_with_fobj_alloc(fobj, NULL);
	TEE_Result res = TEE_SUCCESS;

	fobj_put(fobj);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = vm_map(&utc->uctx, va, num_pgs * SMALL_PAGE_SIZE,
		     prot, VM_FLAG_LDELF, mobj, 0);
	mobj_put(mobj);

	return res;
}

/*
 * This function may leave a few mappings behind on error, but that's taken
 * care of by tee_ta_init_user_ta_session() since the entire context is
 * removed then.
 */
static TEE_Result load_ldelf(struct user_ta_ctx *utc)
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t stack_addr = 0;
	vaddr_t code_addr = 0;
	vaddr_t rw_addr = 0;

	utc->is_32bit = is_arm32;

	res = alloc_and_map_ldelf_fobj(utc, LDELF_STACK_SIZE,
				       TEE_MATTR_URW | TEE_MATTR_PRW,
				       &stack_addr);
	if (res)
		return res;
	utc->ldelf_stack_ptr = stack_addr + LDELF_STACK_SIZE;

	res = alloc_and_map_ldelf_fobj(utc, ldelf_code_size, TEE_MATTR_PRW,
				       &code_addr);
	if (res)
		return res;
	utc->entry_func = code_addr + ldelf_entry;

	rw_addr = ROUNDUP(code_addr + ldelf_code_size, SMALL_PAGE_SIZE);
	res = alloc_and_map_ldelf_fobj(utc, ldelf_data_size,
				       TEE_MATTR_URW | TEE_MATTR_PRW, &rw_addr);
	if (res)
		return res;

	tee_mmu_set_ctx(&utc->ta_ctx.ts_ctx);

	memcpy((void *)code_addr, ldelf_data, ldelf_code_size);
	memcpy((void *)rw_addr, ldelf_data + ldelf_code_size, ldelf_data_size);

	res = vm_set_prot(&utc->uctx, code_addr,
			  ROUNDUP(ldelf_code_size, SMALL_PAGE_SIZE),
			  TEE_MATTR_URX);
	if (res)
		return res;

	DMSG("ldelf load address %#"PRIxVA, code_addr);

	return TEE_SUCCESS;
}

TEE_Result tee_ta_init_user_ta_session(const TEE_UUID *uuid,
				       struct tee_ta_session *s)
{
	TEE_Result res = TEE_SUCCESS;
	struct user_ta_ctx *utc = NULL;

	utc = calloc(1, sizeof(struct user_ta_ctx));
	if (!utc)
		return TEE_ERROR_OUT_OF_MEMORY;

	utc->ta_ctx.initializing = true;
	utc->is_initializing = true;
	TAILQ_INIT(&utc->open_sessions);
	TAILQ_INIT(&utc->cryp_states);
	TAILQ_INIT(&utc->objects);
	TAILQ_INIT(&utc->storage_enums);
	condvar_init(&utc->ta_ctx.busy_cv);
	utc->ta_ctx.ref_count = 1;

	utc->uctx.ts_ctx = &utc->ta_ctx.ts_ctx;

	/*
	 * Set context TA operation structure. It is required by generic
	 * implementation to identify userland TA versus pseudo TA contexts.
	 */
	set_ta_ctx_ops(&utc->ta_ctx);

	utc->ta_ctx.ts_ctx.uuid = *uuid;
	res = vm_info_init(&utc->uctx);
	if (res)
		goto out;

	mutex_lock(&tee_ta_mutex);
	s->ts_sess.ctx = &utc->ta_ctx.ts_ctx;
	/*
	 * Another thread trying to load this same TA may need to wait
	 * until this context is fully initialized. This is needed to
	 * handle single instance TAs.
	 */
	TAILQ_INSERT_TAIL(&tee_ctxes, &utc->ta_ctx, link);
	mutex_unlock(&tee_ta_mutex);

	/*
	 * We must not hold tee_ta_mutex while allocating page tables as
	 * that may otherwise lead to a deadlock.
	 */
	ts_push_current_session(&s->ts_sess);

	res = load_ldelf(utc);
	if (!res)
		res = init_with_ldelf(&s->ts_sess, utc);

	ts_pop_current_session();

	mutex_lock(&tee_ta_mutex);

	if (!res) {
		utc->is_initializing = false;
	} else {
		s->ts_sess.ctx = NULL;
		TAILQ_REMOVE(&tee_ctxes, &utc->ta_ctx, link);
	}

	/* The state has changed for the context, notify eventual waiters. */
	condvar_broadcast(&tee_ta_init_cv);

	mutex_unlock(&tee_ta_mutex);

out:
	if (res) {
		condvar_destroy(&utc->ta_ctx.busy_cv);
		pgt_flush_ctx(&utc->ta_ctx.ts_ctx);
		free_utc(utc);
	}

	return res;
}
