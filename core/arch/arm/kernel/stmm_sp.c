// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */

#include <crypto/crypto.h>
#include <keep.h>
#include <kernel/abort.h>
#include <kernel/stmm_sp.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread_private.h>
#include <kernel/user_mode_ctx.h>
#include <mempool.h>
#include <mm/fobj.h>
#include <mm/mobj.h>
#include <mm/vm.h>
#include <pta_stmm.h>
#include <tee_api_defines_extensions.h>
#include <tee/tee_pobj.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_storage.h>
#include <zlib.h>

#include "stmm_sp_ffa.h"

static const TEE_UUID stmm_uuid = PTA_STMM_UUID;

/*
 * Once a complete FFA spec is added, these will become discoverable.
 * Until then these are considered part of the internal ABI between
 * OP-TEE and StMM.
 */
static const uint16_t stmm_id = 1U;
static const uint16_t stmm_pta_id = 2U;

static_assert(CFG_STMM_HEAP_PAGE_COUNT >= 402,
	      "CFG_STMM_HEAP_PAGE_COUNT must be at least 402");

static const unsigned int stmm_heap_size = CFG_STMM_HEAP_PAGE_COUNT *
					   SMALL_PAGE_SIZE;
static const unsigned int stmm_sec_buf_size = 4 * SMALL_PAGE_SIZE;
static const unsigned int stmm_ns_comm_buf_size = 4 * SMALL_PAGE_SIZE;

extern unsigned char stmm_image[];
extern const unsigned int stmm_image_size;
extern const unsigned int stmm_image_uncompressed_size;

const TEE_UUID *stmm_get_uuid(void)
{
	return &stmm_uuid;
}

static struct stmm_ctx *stmm_alloc_ctx(const TEE_UUID *uuid)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct stmm_ctx *spc = NULL;

	spc = calloc(1, sizeof(*spc));
	if (!spc)
		return NULL;

	spc->ta_ctx.ts_ctx.ops = &stmm_sp_ops;
	spc->ta_ctx.ts_ctx.uuid = *uuid;
	spc->ta_ctx.flags = TA_FLAG_SINGLE_INSTANCE |
			    TA_FLAG_INSTANCE_KEEP_ALIVE;

	res = vm_info_init(&spc->uctx, &spc->ta_ctx.ts_ctx);
	if (res) {
		free(spc);
		return NULL;
	}

	spc->ta_ctx.ref_count = 1;
	condvar_init(&spc->ta_ctx.busy_cv);

	return spc;
}

static TEE_Result stmm_enter_user_mode(struct stmm_ctx *spc)
{
	uint32_t exceptions = 0;
	uint32_t panic_code = 0;
	uint32_t panicked = 0;
	uint64_t cntkctl = 0;

	exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	cntkctl = read_cntkctl();
	write_cntkctl(cntkctl | CNTKCTL_PL0PCTEN);

#ifdef ARM32
	/* Handle usr_lr in place of __thread_enter_user_mode() */
	thread_set_usr_lr(spc->regs.usr_lr);
#endif

	__thread_enter_user_mode(&spc->regs, &panicked, &panic_code);

#ifdef ARM32
	spc->regs.usr_lr = thread_get_usr_lr();
#endif

	write_cntkctl(cntkctl);
	thread_unmask_exceptions(exceptions);

	thread_user_clear_vfp(&spc->uctx);

	if (panicked) {
		abort_print_current_ts();
		DMSG("stmm panicked with code %#"PRIx32, panic_code);
		return TEE_ERROR_TARGET_DEAD;
	}

	return TEE_SUCCESS;
}

#ifdef ARM64
static void init_stmm_regs(struct stmm_ctx *spc, unsigned long a0,
			   unsigned long a1, unsigned long a2, unsigned long a3,
				 unsigned long pc)
{
	spc->regs.x[0] = a0;
	spc->regs.x[1] = a1;
	spc->regs.x[2] = a2;
	spc->regs.x[3] = a3;
	spc->regs.pc = pc;
}
#endif

#ifdef ARM32
static uint32_t __maybe_unused get_spsr(void)
{
	uint32_t s = 0;

	s = read_cpsr();
	s &= ~(CPSR_MODE_MASK | CPSR_T | ARM32_CPSR_IT_MASK);
	s |= CPSR_MODE_USR;

	return s;
}

static void init_stmm_regs(struct stmm_ctx *spc, unsigned long a0,
			   unsigned long a1, unsigned long a2, unsigned long a3,
				 unsigned long pc)
{
	spc->regs.r0 = a0;
	spc->regs.r1 = a1;
	spc->regs.r2 = a2;
	spc->regs.r3 = a3;
	spc->regs.cpsr = get_spsr();
	spc->regs.pc = pc;
}
#endif

static TEE_Result alloc_and_map_sp_fobj(struct stmm_ctx *spc, size_t sz,
					uint32_t prot, vaddr_t *va)
{
	size_t num_pgs = ROUNDUP_DIV(sz, SMALL_PAGE_SIZE);
	struct fobj *fobj = fobj_ta_mem_alloc(num_pgs);
	TEE_Result res = TEE_SUCCESS;
	struct mobj *mobj = NULL;

	mobj = mobj_with_fobj_alloc(fobj, NULL, TEE_MATTR_MEM_TYPE_TAGGED);
	fobj_put(fobj);
	if (!mobj)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = vm_map(&spc->uctx, va, num_pgs * SMALL_PAGE_SIZE,
		     prot, 0, mobj, 0);
	if (res)
		mobj_put(mobj);

	return TEE_SUCCESS;
}

static void *zalloc(void *opaque __unused, unsigned int items,
		    unsigned int size)
{
	return mempool_alloc(mempool_default, items * size);
}

static void zfree(void *opaque __unused, void *address)
{
	mempool_free(mempool_default, address);
}

static void uncompress_image(void *dst, size_t dst_size, void *src,
			     size_t src_size)
{
	z_stream strm = {
		.next_in = src,
		.avail_in = src_size,
		.next_out = dst,
		.avail_out = dst_size,
		.zalloc = zalloc,
		.zfree = zfree,
	};

	if (inflateInit(&strm) != Z_OK)
		panic("inflateInit");

	if (inflate(&strm, Z_SYNC_FLUSH) != Z_STREAM_END)
		panic("inflate");

	if (inflateEnd(&strm) != Z_OK)
		panic("inflateEnd");
}

static TEE_Result load_stmm(struct stmm_ctx *spc)
{
	struct stmm_ffa_mem mem = { };
	unsigned long boot_info = 0;
	vaddr_t sp_addr = 0;
	vaddr_t stmm_image_addr = 0;
	vaddr_t stmm_heap_addr = 0;
	vaddr_t stmm_ns_comm_buf_addr = 0;
	vaddr_t stmm_sec_buf_addr = 0;
	unsigned int sp_size = 0;
	unsigned int uncompressed_size_roundup = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	uncompressed_size_roundup = ROUNDUP(stmm_image_uncompressed_size,
					    SMALL_PAGE_SIZE);
	sp_size = uncompressed_size_roundup + stmm_heap_size +
		  stmm_sec_buf_size;
	res = alloc_and_map_sp_fobj(spc, sp_size,
				    TEE_MATTR_PRW, &sp_addr);
	if (res)
		return res;

	res = alloc_and_map_sp_fobj(spc, stmm_ns_comm_buf_size,
				    TEE_MATTR_URW | TEE_MATTR_PRW,
				    &stmm_ns_comm_buf_addr);
	/*
	 * We don't need to free the previous instance here, they'll all be
	 * handled during the destruction call (stmm_ctx_destroy())
	 */
	if (res)
		return res;

	stmm_image_addr = sp_addr;
	stmm_heap_addr = stmm_image_addr + uncompressed_size_roundup;
	stmm_sec_buf_addr = stmm_heap_addr + stmm_heap_size;

	mem = (struct stmm_ffa_mem){
		.sp_addr = sp_addr,
		.sp_size = sp_size,
		.image_addr = stmm_image_addr,
		.image_region_size = uncompressed_size_roundup,
		.heap_addr = stmm_heap_addr,
		.heap_size = stmm_heap_size,
		.ns_comm_buf_addr = stmm_ns_comm_buf_addr,
		.ns_comm_buf_size = stmm_ns_comm_buf_size,
		.sec_buf_addr = stmm_sec_buf_addr,
		.sec_buf_size = stmm_sec_buf_size,
	};
	res = stmm_ffa_init(&mem, &boot_info);
	if (res)
		return res;

	vm_set_ctx(&spc->ta_ctx.ts_ctx);
	uncompress_image((void *)stmm_image_addr, stmm_image_uncompressed_size,
			 stmm_image, stmm_image_size);

	res = vm_set_prot(&spc->uctx, stmm_image_addr,
			  uncompressed_size_roundup,
			  TEE_MATTR_URX | TEE_MATTR_PR);
	if (res)
		return res;

	res = vm_set_prot(&spc->uctx, stmm_heap_addr, stmm_heap_size,
			  TEE_MATTR_URW | TEE_MATTR_PRW);
	if (res)
		return res;

	res = vm_set_prot(&spc->uctx, stmm_sec_buf_addr, stmm_sec_buf_size,
			  TEE_MATTR_URW | TEE_MATTR_PRW);
	if (res)
		return res;

	DMSG("stmm load address %#"PRIxVA, stmm_image_addr);

	spc->ns_comm_buf_addr = stmm_ns_comm_buf_addr;
	spc->ns_comm_buf_size = stmm_ns_comm_buf_size;

	init_stmm_regs(spc, boot_info, 0, 0, 0, stmm_image_addr);

	return stmm_enter_user_mode(spc);
}

TEE_Result stmm_init_session(const TEE_UUID *uuid, struct tee_ta_session *sess)
{
	struct stmm_ctx *spc = NULL;

	/* Caller is expected to hold tee_ta_mutex for safe changes in @sess */
	assert(mutex_is_locked(&tee_ta_mutex));

	if (memcmp(uuid, &stmm_uuid, sizeof(*uuid)))
		return TEE_ERROR_ITEM_NOT_FOUND;

	spc = stmm_alloc_ctx(uuid);
	if (!spc)
		return TEE_ERROR_OUT_OF_MEMORY;

	spc->ta_ctx.is_initializing = true;

	sess->ts_sess.ctx = &spc->ta_ctx.ts_ctx;
	sess->ts_sess.handle_scall = sess->ts_sess.ctx->ops->handle_scall;

	return TEE_SUCCESS;
}

TEE_Result stmm_complete_session(struct tee_ta_session *sess)
{
	struct stmm_ctx *spc = to_stmm_ctx(sess->ts_sess.ctx);
	TEE_Result res = TEE_ERROR_GENERIC;

	ts_push_current_session(&sess->ts_sess);
	res = load_stmm(spc);
	ts_pop_current_session();
	vm_set_ctx(NULL);
	if (res) {
		sess->ts_sess.ctx = NULL;
		spc->ta_ctx.ts_ctx.ops->destroy(&spc->ta_ctx.ts_ctx);

		return res;
	}

	mutex_lock(&tee_ta_mutex);
	spc->ta_ctx.is_initializing = false;
	TAILQ_INSERT_TAIL(&tee_ctxes, &spc->ta_ctx, link);
	mutex_unlock(&tee_ta_mutex);

	return TEE_SUCCESS;
}

static TEE_Result stmm_enter_open_session(struct ts_session *s)
{
	struct stmm_ctx *spc = to_stmm_ctx(s->ctx);
	struct tee_ta_session *ta_sess = to_ta_session(s);
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (ta_sess->param->types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (spc->ta_ctx.is_initializing) {
		/* StMM is initialized in stmm_init_session() */
		ta_sess->err_origin = TEE_ORIGIN_TEE;
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result stmm_enter_invoke_cmd(struct ts_session *s, uint32_t cmd)
{
	struct stmm_ctx *spc = to_stmm_ctx(s->ctx);
	struct tee_ta_session *ta_sess = to_ta_session(s);
	TEE_Result res = TEE_SUCCESS;
	TEE_Result __maybe_unused tmp_res = TEE_SUCCESS;
	unsigned int ns_buf_size = 0;
	struct param_mem *mem = NULL;
	void *va = NULL;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (cmd != PTA_STMM_CMD_COMMUNICATE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (ta_sess->param->types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	mem = &ta_sess->param->u[0].mem;
	ns_buf_size = mem->size;
	if (ns_buf_size > spc->ns_comm_buf_size) {
		mem->size = spc->ns_comm_buf_size;
		return TEE_ERROR_EXCESS_DATA;
	}

	res = mobj_inc_map(mem->mobj);
	if (res)
		return res;

	va = mobj_get_va(mem->mobj, mem->offs, mem->size);
	if (!va) {
		EMSG("Can't get a valid VA for NS buffer");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out_va;
	}

	stmm_ffa_set_direct_req(&spc->regs, stmm_pta_id, stmm_id,
				spc->ns_comm_buf_addr, ns_buf_size);

	ts_push_current_session(s);

	memcpy((void *)spc->ns_comm_buf_addr, va, ns_buf_size);

	res = stmm_enter_user_mode(spc);
	if (res)
		goto out_session;
	/*
	 * Copy the SPM response from secure partition back to the non-secure
	 * buffer of the client that called us.
	 */
	ta_sess->param->u[1].val.a =
		stmm_ffa_get_direct_resp_size(&spc->regs);

	memcpy(va, (void *)spc->ns_comm_buf_addr, ns_buf_size);

out_session:
	ts_pop_current_session();
out_va:
	tmp_res = mobj_dec_map(mem->mobj);
	assert(!tmp_res);

	return res;
}

static void stmm_enter_close_session(struct ts_session *s __unused)
{
}

static void stmm_dump_state(struct ts_ctx *ctx)
{
	user_mode_ctx_print_mappings(to_user_mode_ctx(ctx));
}
DECLARE_KEEP_PAGER(stmm_dump_state);

static uint32_t stmm_get_instance_id(struct ts_ctx *ctx)
{
	return to_stmm_ctx(ctx)->uctx.vm_info.asid;
}

static void stmm_ctx_destroy(struct ts_ctx *ctx)
{
	struct stmm_ctx *spc = to_stmm_ctx(ctx);

	vm_info_final(&spc->uctx);
	free(spc);
}

#ifdef ARM64
static void save_sp_ctx(struct stmm_ctx *spc,
			struct thread_scall_regs *regs)
{
	size_t n = 0;

	/* Save the return values from StMM */
	for (n = 0; n <= 7; n++)
		spc->regs.x[n] = *(&regs->x0 + n);

	spc->regs.sp = regs->sp_el0;
	spc->regs.pc = regs->elr;
	spc->regs.cpsr = regs->spsr;
}
#endif

#ifdef ARM32
static void save_sp_ctx(struct stmm_ctx *spc,
			struct thread_scall_regs *regs)
{
	spc->regs.r0 = regs->r0;
	spc->regs.r1 = regs->r1;
	spc->regs.r2 = regs->r2;
	spc->regs.r3 = regs->r3;
	spc->regs.r4 = regs->r4;
	spc->regs.r5 = regs->r5;
	spc->regs.r6 = regs->r6;
	spc->regs.r7 = regs->r7;
	spc->regs.pc = regs->lr;
	spc->regs.cpsr = regs->spsr;
	spc->regs.usr_sp = thread_get_usr_sp();
}
#endif

static void return_from_sp_helper(bool panic, uint32_t panic_code,
				  struct thread_scall_regs *regs)
{
	struct ts_session *sess = ts_get_current_session();
	struct stmm_ctx *spc = to_stmm_ctx(sess->ctx);

	if (panic)
		spc->ta_ctx.panicked = true;
	else
		save_sp_ctx(spc, regs);

	SVC_REGS_A0(regs) = 0;
	SVC_REGS_A1(regs) = panic;
	SVC_REGS_A2(regs) = panic_code;
}

/*
 * Combined read from secure partition, this will open, read and
 * close the file object.
 */
static TEE_Result sec_storage_obj_read(unsigned long storage_id, char *obj_id,
				       unsigned long obj_id_len, void *data,
				       unsigned long len, unsigned long offset,
				       unsigned long flags)
{
	const struct tee_file_operations *fops = NULL;
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct ts_session *sess = NULL;
	struct tee_file_handle *fh = NULL;
	struct tee_pobj *po = NULL;
	size_t file_size = 0;
	size_t read_len = 0;

	fops = tee_svc_storage_file_ops(storage_id);
	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (obj_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	sess = ts_get_current_session();

	res = tee_pobj_get(&sess->ctx->uuid, obj_id, obj_id_len, flags,
			   TEE_POBJ_USAGE_OPEN, fops, &po);
	if (res != TEE_SUCCESS)
		return res;

	res = po->fops->open(po, &file_size, &fh);
	if (res != TEE_SUCCESS)
		goto out;

	read_len = len;
	res = po->fops->read(fh, offset, NULL, data, &read_len);
	if (res == TEE_ERROR_CORRUPT_OBJECT) {
		EMSG("Object corrupt");
		po->fops->remove(po);
	} else if (res == TEE_SUCCESS && len != read_len) {
		res = TEE_ERROR_CORRUPT_OBJECT;
	}

	po->fops->close(&fh);

out:
	tee_pobj_release(po);

	return res;
}

/*
 * Combined write from secure partition, this will create/open, write and
 * close the file object.
 */
static TEE_Result sec_storage_obj_write(unsigned long storage_id, char *obj_id,
					unsigned long obj_id_len, void *data,
					unsigned long len, unsigned long offset,
					unsigned long flags)

{
	const struct tee_file_operations *fops = NULL;
	struct ts_session *sess = NULL;
	struct tee_file_handle *fh = NULL;
	TEE_Result res = TEE_SUCCESS;
	struct tee_pobj *po = NULL;

	fops = tee_svc_storage_file_ops(storage_id);
	if (!fops)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (obj_id_len > TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	sess = ts_get_current_session();

	res = tee_pobj_get(&sess->ctx->uuid, obj_id, obj_id_len, flags,
			   TEE_POBJ_USAGE_OPEN, fops, &po);
	if (res != TEE_SUCCESS)
		return res;

	res = po->fops->open(po, NULL, &fh);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = po->fops->create(po, false, NULL, 0, NULL, 0,
				       NULL, NULL, 0, &fh);
	if (res == TEE_SUCCESS) {
		res = po->fops->write(fh, offset, NULL, data, len);
		po->fops->close(&fh);
	}

	tee_pobj_release(po);

	return res;
}

#define FILENAME "EFI_VARS"
static void stmm_handle_storage_service(struct thread_scall_regs *regs)
{
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_SHARE_READ |
			 TEE_DATA_FLAG_SHARE_WRITE;
	struct stmm_ffa_storage_req req = { };
	char obj_id[] = FILENAME;
	size_t obj_id_len = strlen(obj_id);
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	stmm_ffa_get_storage_req(regs, &req);
	switch (req.op) {
	case STMM_FFA_STORAGE_OP_READ:
		DMSG("RPMB read");
		res = sec_storage_obj_read(TEE_STORAGE_PRIVATE_RPMB, obj_id,
					   obj_id_len, req.data, req.data_len,
					   req.offset, flags);
		break;
	case STMM_FFA_STORAGE_OP_WRITE:
		DMSG("RPMB write");
		res = sec_storage_obj_write(TEE_STORAGE_PRIVATE_RPMB, obj_id,
					    obj_id_len, req.data, req.data_len,
					    req.offset, flags);
		break;
	case STMM_FFA_STORAGE_OP_INVALID:
		break;
	default:
		panic();
	}

	stmm_ffa_complete_storage(regs, res);
}

/* Return true if returning to SP, false if returning to caller */
static bool spm_handle_scall(struct thread_scall_regs *regs)
{
	struct ts_session *sess = ts_get_current_session();
	struct stmm_ctx *spc = to_stmm_ctx(sess->ctx);

	switch (stmm_ffa_handle_scall(&spc->uctx, regs)) {
	case STMM_FFA_RESUME:
		return true;
	case STMM_FFA_RETURN:
		return_from_sp_helper(false, 0, regs);
		return false;
	case STMM_FFA_STORAGE:
		stmm_handle_storage_service(regs);
		return true;
	case STMM_FFA_PANIC:
		return_from_sp_helper(true, 0xabcd, regs);
		return false;
	default:
		panic();
	}
}

/*
 * Note: this variable is weak just to ease breaking its dependency chain
 * when added to the unpaged area.
 */
const struct ts_ops stmm_sp_ops __weak __relrodata_unpaged("stmm_sp_ops") = {
	.enter_open_session = stmm_enter_open_session,
	.enter_invoke_cmd = stmm_enter_invoke_cmd,
	.enter_close_session = stmm_enter_close_session,
	.dump_state = stmm_dump_state,
	.destroy = stmm_ctx_destroy,
	.get_instance_id = stmm_get_instance_id,
	.handle_scall = spm_handle_scall,
};
