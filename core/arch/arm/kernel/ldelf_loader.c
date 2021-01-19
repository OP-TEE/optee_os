// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2015-2020, Linaro Limited
 * Copyright (c) 2020-2021, Arm Limited
 */

#include <assert.h>
#include <kernel/ldelf_loader.h>
#include <kernel/ldelf_syscalls.h>
#include <ldelf.h>
#include <mm/mobj.h>
#include <mm/vm.h>
#include <tee/arch_svc.h>

extern uint8_t ldelf_data[];
extern const unsigned int ldelf_code_size;
extern const unsigned int ldelf_data_size;
extern const unsigned int ldelf_entry;

/* ldelf has the same architecture/register width as the kernel */
#ifdef ARM32
static const bool is_arm32 = true;
#else
static const bool is_arm32;
#endif

static TEE_Result alloc_and_map_ldelf_fobj(struct user_mode_ctx *uctx,
					   size_t sz, uint32_t prot,
					   vaddr_t *va)
{
	size_t num_pgs = ROUNDUP(sz, SMALL_PAGE_SIZE) / SMALL_PAGE_SIZE;
	struct fobj *fobj = fobj_ta_mem_alloc(num_pgs);
	struct mobj *mobj = mobj_with_fobj_alloc(fobj, NULL);
	TEE_Result res = TEE_SUCCESS;

	fobj_put(fobj);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = vm_map(uctx, va, num_pgs * SMALL_PAGE_SIZE,
		     prot, VM_FLAG_LDELF, mobj, 0);
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

	uctx->is_32bit = is_arm32;

	res = alloc_and_map_ldelf_fobj(uctx, LDELF_STACK_SIZE,
				       TEE_MATTR_URW | TEE_MATTR_PRW,
				       &stack_addr);
	if (res)
		return res;
	uctx->ldelf_stack_ptr = stack_addr + LDELF_STACK_SIZE;

	res = alloc_and_map_ldelf_fobj(uctx, ldelf_code_size, TEE_MATTR_PRW,
				       &code_addr);
	if (res)
		return res;
	uctx->entry_func = code_addr + ldelf_entry;

	rw_addr = ROUNDUP(code_addr + ldelf_code_size, SMALL_PAGE_SIZE);
	res = alloc_and_map_ldelf_fobj(uctx, ldelf_data_size,
				       TEE_MATTR_URW | TEE_MATTR_PRW, &rw_addr);
	if (res)
		return res;

	vm_set_ctx(uctx->ts_ctx);

	memcpy((void *)code_addr, ldelf_data, ldelf_code_size);
	memcpy((void *)rw_addr, ldelf_data + ldelf_code_size, ldelf_data_size);

	res = vm_set_prot(uctx, code_addr,
			  ROUNDUP(ldelf_code_size, SMALL_PAGE_SIZE),
			  TEE_MATTR_URX);
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

	usr_stack = uctx->ldelf_stack_ptr;
	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	arg = (struct ldelf_arg *)usr_stack;
	memset(arg, 0, sizeof(*arg));
	arg->uuid = uctx->ts_ctx->uuid;
	sess->handle_svc = ldelf_handle_svc;

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, uctx->entry_func,
				     is_arm32, &panicked, &panic_code);

	sess->handle_svc = sess->ctx->ops->handle_svc;
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

	res = vm_check_access_rights(uctx,
				     TEE_MEMORY_ACCESS_READ |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)arg, sizeof(*arg));
	if (res)
		return res;

	if (is_user_ta_ctx(uctx->ts_ctx)) {
		/*
		 * This is already checked by the elf loader, but since it runs
		 * in user mode we're not trusting it entirely.
		 */
		if (arg->flags & ~TA_FLAGS_MASK)
			return TEE_ERROR_BAD_FORMAT;

		to_user_ta_ctx(uctx->ts_ctx)->ta_ctx.flags = arg->flags;
	}

	uctx->is_32bit = arg->is_32bit;
	uctx->entry_func = arg->entry_func;
	uctx->stack_ptr = arg->stack_ptr;
	uctx->dump_entry_func = arg->dump_entry;
#ifdef CFG_FTRACE_SUPPORT
	uctx->ftrace_entry_func = arg->ftrace_entry;
	sess->fbuf = arg->fbuf;
#endif
	uctx->dl_entry_func = arg->dl_entry;

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
	size_t n = 0;

	TAILQ_FOREACH(r, &uctx->vm_info.regions, link)
		if (r->attr & TEE_MATTR_URWX)
			n++;

	usr_stack = uctx->ldelf_stack_ptr;
	usr_stack -= ROUNDUP(sizeof(*arg) + n * sizeof(struct dump_map),
			     STACK_ALIGNMENT);
	arg = (struct dump_entry_arg *)usr_stack;

	res = vm_check_access_rights(uctx,
				     TEE_MEMORY_ACCESS_READ |
				     TEE_MEMORY_ACCESS_ANY_OWNER,
				     (uaddr_t)arg, sizeof(*arg));
	if (res) {
		EMSG("ldelf stack is inaccessible!");
		return res;
	}

	memset(arg, 0, sizeof(*arg) + n * sizeof(struct dump_map));

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

	arg->is_arm32 = uctx->is_32bit;
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

	sess = ts_get_current_session();
	sess->handle_svc = ldelf_handle_svc;

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, uctx->dump_entry_func,
				     is_arm32, &panicked, &panic_code);

	sess->handle_svc = sess->ctx->ops->handle_svc;
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
	sess->handle_svc = ldelf_handle_svc;

	res = thread_enter_user_mode((vaddr_t)buf, (vaddr_t)arg, 0, 0,
				     usr_stack, uctx->ftrace_entry_func,
				     is_arm32, &panicked, &panic_code);

	sess->handle_svc = sess->ctx->ops->handle_svc;
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
	struct dl_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	struct ts_session *sess = NULL;

	assert(uuid);

	usr_stack -= ROUNDUP(sizeof(*arg), STACK_ALIGNMENT);
	arg = (struct dl_entry_arg *)usr_stack;

	res = vm_check_access_rights(uctx,
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

	sess = ts_get_current_session();
	sess->handle_svc = ldelf_handle_svc;

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, uctx->dl_entry_func,
				     is_arm32, &panicked, &panic_code);

	sess->handle_svc = sess->ctx->ops->handle_svc;
	ldelf_sess_cleanup(sess);

	if (panicked) {
		EMSG("ldelf dl_entry function panicked");
		abort_print_current_ts();
		res = TEE_ERROR_TARGET_DEAD;
	}
	if (!res)
		res = arg->ret;

	return res;
}

TEE_Result ldelf_dlsym(struct user_mode_ctx *uctx, TEE_UUID *uuid,
		       const char *sym, size_t maxlen, vaddr_t *val)
{
	uaddr_t usr_stack = uctx->ldelf_stack_ptr;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct dl_entry_arg *arg = NULL;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	size_t len = strnlen(sym, maxlen);
	struct ts_session *sess = NULL;

	if (len == maxlen)
		return TEE_ERROR_BAD_PARAMETERS;

	usr_stack -= ROUNDUP(sizeof(*arg) + len + 1, STACK_ALIGNMENT);
	arg = (struct dl_entry_arg *)usr_stack;

	res = vm_check_access_rights(uctx,
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

	sess = ts_get_current_session();
	sess->handle_svc = ldelf_handle_svc;

	res = thread_enter_user_mode((vaddr_t)arg, 0, 0, 0,
				     usr_stack, uctx->dl_entry_func,
				     is_arm32, &panicked, &panic_code);

	sess->handle_svc = sess->ctx->ops->handle_svc;
	ldelf_sess_cleanup(sess);

	if (panicked) {
		EMSG("ldelf dl_entry function panicked");
		abort_print_current_ts();
		res = TEE_ERROR_TARGET_DEAD;
	}
	if (!res) {
		res = arg->ret;
		if (!res)
			*val = arg->dlsym.val;
	}

	return res;
}
