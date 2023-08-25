// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2020, 2022 Linaro Limited
 * Copyright (c) 2020-2023, Arm Limited
 */

#include <assert.h>
#include <kernel/ldelf_loader.h>
#include <kernel/ldelf_syscalls.h>
#include <kernel/scall.h>
#include <kernel/user_access.h>
#include <ldelf.h>
#include <mm/mobj.h>
#include <mm/vm.h>

#define BOUNCE_BUFFER_SIZE	4096

extern uint8_t ldelf_data[];
extern const unsigned int ldelf_code_size;
extern const unsigned int ldelf_data_size;
extern const unsigned int ldelf_entry;

/* ldelf has the same architecture/register width as the kernel */
#if defined(ARM32) || defined(RV32)
static const bool is_32bit = true;
#else
static const bool is_32bit;
#endif

static TEE_Result alloc_and_map_fobj(struct user_mode_ctx *uctx, size_t sz,
				     uint32_t prot, uint32_t flags, vaddr_t *va)
{
	size_t num_pgs = ROUNDUP(sz, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE;
	struct fobj *fobj = fobj_ta_mem_alloc(num_pgs);
	struct mobj *mobj = mobj_with_fobj_alloc(fobj, NULL,
						 TEE_MATTR_MEM_TYPE_TAGGED);
	TEE_Result res = TEE_SUCCESS;

	fobj_put(fobj);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = vm_map(uctx, va, num_pgs * SMALL_PAGE_SIZE, prot, flags, mobj, 0);
	mobj_put(mobj);

	return res;
}

/*
 * This function may leave a few mappings behind on error, but that's taken
 * care of by tee_ta_init_user_ta_session() since the entire context is
 * removed then.
 */
TEE_Result ldelf_load_ldelf(struct user_mode_ctx *uctx)
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t stack_addr = 0;
	vaddr_t code_addr = 0;
	vaddr_t rw_addr = 0;
	vaddr_t bb_addr = 0;
	uint32_t prot = 0;

	uctx->is_32bit = is_32bit;

	res = alloc_and_map_fobj(uctx, BOUNCE_BUFFER_SIZE, TEE_MATTR_PRW, 0,
				 &bb_addr);
	if (res)
		return res;
	uctx->bbuf = (void *)bb_addr;
	uctx->bbuf_size = BOUNCE_BUFFER_SIZE;

	res = alloc_and_map_fobj(uctx, LDELF_STACK_SIZE,
				 TEE_MATTR_URW | TEE_MATTR_PRW, VM_FLAG_LDELF,
				 &stack_addr);
	if (res)
		return res;
	uctx->ldelf_stack_ptr = stack_addr + LDELF_STACK_SIZE;

	res = alloc_and_map_fobj(uctx, ldelf_code_size, TEE_MATTR_PRW,
				 VM_FLAG_LDELF, &code_addr);
	if (res)
		return res;
	uctx->entry_func = code_addr + ldelf_entry;

	rw_addr = ROUNDUP(code_addr + ldelf_code_size, SMALL_PAGE_SIZE);
	res = alloc_and_map_fobj(uctx, ldelf_data_size,
				 TEE_MATTR_URW | TEE_MATTR_PRW, VM_FLAG_LDELF,
				 &rw_addr);
	if (res)
		return res;

	vm_set_ctx(uctx->ts_ctx);

	memcpy((void *)code_addr, ldelf_data, ldelf_code_size);

	res = copy_to_user((void *)rw_addr, ldelf_data + ldelf_code_size,
			   ldelf_data_size);
	if (res)
		return res;

	prot = TEE_MATTR_URX;
	if (IS_ENABLED(CFG_CORE_BTI))
		prot |= TEE_MATTR_GUARDED;

	res = vm_set_prot(uctx, code_addr,
			  ROUNDUP(ldelf_code_size, SMALL_PAGE_SIZE), prot);
	if (res)
		return res;

	DMSG("ldelf load address %#"PRIxVA, code_addr);

	return TEE_SUCCESS;
}

TEE_Result ldelf_init_with_ldelf(struct ts_session *sess,
				 struct user_mode_ctx *uctx)
{
	TEE_Result res = TEE_SUCCESS;
	struct ldelf_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	uaddr_t usr_stack = 0;
	struct ldelf_arg *arg_bbuf = NULL;

	usr_stack = uctx->ldelf_stack_ptr;
	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	arg = (struct ldelf_arg *)usr_stack;
	sess->handle_scall = scall_handle_ldelf;

	res = clear_user(arg, sizeof(*arg));
	if (res)
		return res;

	res = PUT_USER_SCALAR(uctx->ts_ctx->uuid, &arg->uuid);
	if (res)
		return res;

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, uctx->entry_func,
				     is_32bit, &panicked, &panic_code);

	sess->handle_scall = sess->ctx->ops->handle_scall;
	thread_user_clear_vfp(uctx);
	ldelf_sess_cleanup(sess);

	if (panicked) {
		abort_print_current_ts();
		EMSG("ldelf panicked");
		return TEE_ERROR_GENERIC;
	}
	if (res) {
		EMSG("ldelf failed with res: %#"PRIx32, res);
		return res;
	}

	res = BB_MEMDUP_USER(arg, sizeof(*arg), &arg_bbuf);
	if (res)
		return res;

	if (is_user_ta_ctx(uctx->ts_ctx)) {
		/*
		 * This is already checked by the elf loader, but since it runs
		 * in user mode we're not trusting it entirely.
		 */
		if (arg_bbuf->flags & ~TA_FLAGS_MASK)
			return TEE_ERROR_BAD_FORMAT;

		to_user_ta_ctx(uctx->ts_ctx)->ta_ctx.flags = arg_bbuf->flags;
	}

	uctx->is_32bit = arg_bbuf->is_32bit;
	uctx->entry_func = arg_bbuf->entry_func;
	uctx->load_addr = arg_bbuf->load_addr;
	uctx->stack_ptr = arg_bbuf->stack_ptr;
	uctx->dump_entry_func = arg_bbuf->dump_entry;
#ifdef CFG_FTRACE_SUPPORT
	uctx->ftrace_entry_func = arg_bbuf->ftrace_entry;
	sess->fbuf = arg_bbuf->fbuf;
#endif
	uctx->dl_entry_func = arg_bbuf->dl_entry;

	bb_free(arg_bbuf, sizeof(*arg));

	return TEE_SUCCESS;
}

TEE_Result ldelf_dump_state(struct user_mode_ctx *uctx)
{
	TEE_Result res = TEE_SUCCESS;
	uaddr_t usr_stack = uctx->ldelf_stack_ptr;
	struct dump_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	struct thread_specific_data *tsd = thread_get_tsd();
	struct ts_session *sess = NULL;
	struct vm_region *r = NULL;
	size_t arg_size = 0;
	size_t n = 0;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link)
		if (r->attr & TEE_MATTR_URWX)
			n++;

	arg_size = ROUNDUP(sizeof(*arg) + n * sizeof(struct dump_map),
			   STACK_ALIGNMENT);

	usr_stack = uctx->ldelf_stack_ptr;
	usr_stack -= arg_size;

	arg = bb_alloc(arg_size);
	if (!arg)
		return TEE_ERROR_OUT_OF_MEMORY;
	memset(arg, 0, arg_size);

	arg->num_maps = n;
	n = 0;
	TAILQ_FOREACH(r, &uctx->vm_info.regions, link) {
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

	arg->is_32bit = uctx->is_32bit;
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
	if (uctx->is_32bit) {
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
#if defined(RV64) || defined(RV32)
	arg->rv.fp = tsd->abort_regs.s0;
	arg->rv.pc = tsd->abort_regs.epc;
	arg->rv.sp = tsd->abort_regs.sp;
#endif /*RV64||RV32*/

	res = copy_to_user((void *)usr_stack, arg, arg_size);
	if (res)
		return res;

	sess = ts_get_current_session();
	sess->handle_scall = scall_handle_ldelf;

	res = thread_enter_user_mode(usr_stack, 0, 0, 0,
				     usr_stack, uctx->dump_entry_func,
				     is_32bit, &panicked, &panic_code);

	sess->handle_scall = sess->ctx->ops->handle_scall;
	thread_user_clear_vfp(uctx);
	ldelf_sess_cleanup(sess);

	if (panicked) {
		uctx->dump_entry_func = 0;
		EMSG("ldelf dump function panicked");
		abort_print_current_ts();
		res = TEE_ERROR_TARGET_DEAD;
	}

	return res;
}

#ifdef CFG_FTRACE_SUPPORT
TEE_Result ldelf_dump_ftrace(struct user_mode_ctx *uctx,
			     void *buf, size_t *blen)
{
	uaddr_t usr_stack = uctx->ldelf_stack_ptr;
	TEE_Result res = TEE_SUCCESS;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	size_t *arg = NULL;
	struct ts_session *sess = NULL;

	if (!uctx->ftrace_entry_func)
		return TEE_ERROR_NOT_SUPPORTED;

	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	arg = (size_t *)usr_stack;

	res = vm_check_access_rights(uctx,
				     TEE_MEMORY_ACCESS_READ |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)arg, sizeof(*arg));
	if (res) {
		EMSG("ldelf stack is inaccessible!");
		return res;
	}

	*arg = *blen;

	sess = ts_get_current_session();
	sess->handle_scall = scall_handle_ldelf;

	res = thread_enter_user_mode((vaddr_t)buf, (vaddr_t)arg, 0, 0,
				     usr_stack, uctx->ftrace_entry_func,
				     is_32bit, &panicked, &panic_code);

	sess->handle_scall = sess->ctx->ops->handle_scall;
	thread_user_clear_vfp(uctx);
	ldelf_sess_cleanup(sess);

	if (panicked) {
		uctx->ftrace_entry_func = 0;
		EMSG("ldelf ftrace function panicked");
		abort_print_current_ts();
		res = TEE_ERROR_TARGET_DEAD;
	}

	if (!res) {
		if (*arg > *blen)
			res = TEE_ERROR_SHORT_BUFFER;
		*blen = *arg;
	}

	return res;
}
#endif /*CFG_FTRACE_SUPPORT*/

TEE_Result ldelf_dlopen(struct user_mode_ctx *uctx, TEE_UUID *uuid,
			uint32_t flags)
{
	uaddr_t usr_stack = uctx->ldelf_stack_ptr;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dl_entry_arg *usr_arg = NULL;
	struct dl_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	struct ts_session *sess = NULL;

	assert(uuid);

	arg = bb_alloc(sizeof(*arg));
	if (!arg)
		return TEE_ERROR_OUT_OF_MEMORY;

	memset(arg, 0, sizeof(*arg));
	arg->cmd = LDELF_DL_ENTRY_DLOPEN;
	arg->dlopen.uuid = *uuid;
	arg->dlopen.flags = flags;

	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	usr_arg = (void *)usr_stack;

	res = copy_to_user(usr_arg, arg, sizeof(*arg));
	if (res)
		return res;

	sess = ts_get_current_session();
	sess->handle_scall = scall_handle_ldelf;

	res = thread_enter_user_mode(usr_stack, 0, 0, 0,
				     usr_stack, uctx->dl_entry_func,
				     is_32bit, &panicked, &panic_code);

	sess->handle_scall = sess->ctx->ops->handle_scall;
	ldelf_sess_cleanup(sess);

	if (panicked) {
		EMSG("ldelf dl_entry function panicked");
		abort_print_current_ts();
		res = TEE_ERROR_TARGET_DEAD;
	}
	if (!res) {
		TEE_Result res2 = TEE_SUCCESS;

		res2 = GET_USER_SCALAR(res, &usr_arg->ret);
		if (res2)
			res = res2;
	}

	return res;
}

TEE_Result ldelf_dlsym(struct user_mode_ctx *uctx, TEE_UUID *uuid,
		       const char *sym, size_t symlen, vaddr_t *val)
{
	uaddr_t usr_stack = uctx->ldelf_stack_ptr;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dl_entry_arg *usr_arg = NULL;
	struct dl_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	struct ts_session *sess = NULL;

	usr_stack -= ROUNDUP(sizeof(*arg) + symlen + 1, STACK_ALIGNMENT);
	usr_arg = (void *)usr_stack;
	arg = bb_alloc(sizeof(*arg));
	if (!arg)
		return TEE_ERROR_OUT_OF_MEMORY;
	memset(arg, 0, sizeof(*arg));
	arg->cmd = LDELF_DL_ENTRY_DLSYM;
	arg->dlsym.uuid = *uuid;
	res = copy_to_user(usr_arg, arg, sizeof(*arg));
	if (res)
		return res;
	res = copy_to_user(usr_arg->dlsym.symbol, sym, symlen + 1);
	if (res)
		return res;

	sess = ts_get_current_session();
	sess->handle_scall = scall_handle_ldelf;

	res = thread_enter_user_mode((vaddr_t)usr_arg, 0, 0, 0,
				     usr_stack, uctx->dl_entry_func,
				     is_32bit, &panicked, &panic_code);

	sess->handle_scall = sess->ctx->ops->handle_scall;
	ldelf_sess_cleanup(sess);

	if (panicked) {
		EMSG("ldelf dl_entry function panicked");
		abort_print_current_ts();
		res = TEE_ERROR_TARGET_DEAD;
	}
	if (!res) {
		TEE_Result res2 = TEE_SUCCESS;

		res2 = GET_USER_SCALAR(res, &usr_arg->ret);
		if (res2)
			res = res2;
		if (!res)
			res = GET_USER_SCALAR(*val, &usr_arg->dlsym.val);
	}

	return res;
}
