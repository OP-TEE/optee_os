// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */

#include <crypto/crypto.h>
#include <efi/hob.h>
#include <ffa.h>
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

#ifdef ARM64
#define SVC_REGS_A0(_regs)	((_regs)->x0)
#define SVC_REGS_A1(_regs)	((_regs)->x1)
#define SVC_REGS_A2(_regs)	((_regs)->x2)
#define SVC_REGS_A3(_regs)	((_regs)->x3)
#define SVC_REGS_A4(_regs)	((_regs)->x4)
#define SVC_REGS_A5(_regs)	((_regs)->x5)
#define SVC_REGS_A6(_regs)	((_regs)->x6)
#define SVC_REGS_A7(_regs)	((_regs)->x7)
#define __FFA_SVC_RPMB_READ		FFA_SVC_RPMB_READ
#define __FFA_SVC_RPMB_WRITE		FFA_SVC_RPMB_WRITE
#define __FFA_MSG_SEND_DIRECT_RESP	FFA_MSG_SEND_DIRECT_RESP_64
#define __FFA_MSG_SEND_DIRECT_REQ	FFA_MSG_SEND_DIRECT_REQ_64
#define __FFA_MEM_PERM_GET	FFA_MEM_PERM_GET_64
#define __FFA_MEM_PERM_SET	FFA_MEM_PERM_SET_64
#endif
#ifdef ARM32
#define SVC_REGS_A0(_regs)	((_regs)->r0)
#define SVC_REGS_A1(_regs)	((_regs)->r1)
#define SVC_REGS_A2(_regs)	((_regs)->r2)
#define SVC_REGS_A3(_regs)	((_regs)->r3)
#define SVC_REGS_A4(_regs)	((_regs)->r4)
#define SVC_REGS_A5(_regs)	((_regs)->r5)
#define SVC_REGS_A6(_regs)	((_regs)->r6)
#define SVC_REGS_A7(_regs)	((_regs)->r7)
#define __FFA_SVC_RPMB_READ		FFA_SVC_RPMB_READ_32
#define __FFA_SVC_RPMB_WRITE		FFA_SVC_RPMB_WRITE_32
#define __FFA_MSG_SEND_DIRECT_RESP	FFA_MSG_SEND_DIRECT_RESP_32
#define __FFA_MSG_SEND_DIRECT_REQ	FFA_MSG_SEND_DIRECT_REQ_32
#define __FFA_MEM_PERM_GET	FFA_MEM_PERM_GET_32
#define __FFA_MEM_PERM_SET	FFA_MEM_PERM_SET_32
#endif

static const TEE_UUID stmm_uuid = PTA_STMM_UUID;
static TEE_UUID ns_buf_guid = MM_NS_BUFFER_GUID;
static TEE_UUID mmram_resv_guid = MM_PEI_MMRAM_MEMORY_RESERVE_GUID;

/*
 * Once a complete FFA spec is added, these will become discoverable.
 * Until then these are considered part of the internal ABI between
 * OP-TEE and StMM.
 */
static const uint16_t stmm_id = 1U;
static const uint16_t stmm_pta_id = 2U;
static const uint16_t ffa_storage_id = 4U;

static const unsigned int stmm_heap_size = 402 * SMALL_PAGE_SIZE;
static const unsigned int stmm_sec_buf_size = 4 * SMALL_PAGE_SIZE;
static const unsigned int stmm_ns_comm_buf_size = 4 * SMALL_PAGE_SIZE;

extern unsigned char stmm_image[];
extern const unsigned int stmm_image_size;
extern const unsigned int stmm_image_uncompressed_size;

static vaddr_t stmm_image_addr;
static vaddr_t stmm_heap_addr;
static vaddr_t stmm_ns_comm_buf_addr;
static vaddr_t stmm_sec_buf_addr;

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

static struct efi_hob_handoff_info_table *
build_stmm_boot_hob_list(vaddr_t sp_addr,
			 uint32_t sp_size, uint32_t *hob_table_size)
{
	struct efi_hob_handoff_info_table *hob_table = NULL;
	unsigned int uncompressed_size_roundup = 0;
	struct efi_mmram_descriptor *mmram_desc_data = NULL;
	struct efi_mmram_hob_descriptor_block *mmram_resv_data = NULL;
	uint16_t mmram_resv_data_size = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t hob_table_offset = 0;
	void *guid_hob_data = NULL;

	uncompressed_size_roundup = ROUNDUP(stmm_image_uncompressed_size,
					    SMALL_PAGE_SIZE);
	stmm_image_addr = sp_addr;
	stmm_heap_addr = stmm_image_addr + uncompressed_size_roundup;
	stmm_sec_buf_addr = stmm_heap_addr + stmm_heap_size;
	hob_table_offset = sizeof(struct ffa_boot_info_header_1_1) +
			   sizeof(struct ffa_boot_info_1_1);

	hob_table = efi_create_hob_list(sp_addr, sp_size,
					stmm_sec_buf_addr + hob_table_offset,
					stmm_sec_buf_size - hob_table_offset);
	if (!hob_table) {
		EMSG("Failed to create hob_table.");
		return NULL;
	}

	ret = efi_create_fv_hob(hob_table, sp_addr, uncompressed_size_roundup);
	if (ret) {
		EMSG("Failed to create fv hob.");
		return NULL;
	}

	ret = efi_create_guid_hob(hob_table, &ns_buf_guid,
				  sizeof(struct efi_mmram_descriptor),
				  &guid_hob_data);
	if (ret) {
		EMSG("Failed to create ns buffer hob.");
		return NULL;
	}

	mmram_desc_data = guid_hob_data;
	mmram_desc_data->physical_start = stmm_ns_comm_buf_addr;
	mmram_desc_data->physical_size = stmm_ns_comm_buf_size;
	mmram_desc_data->cpu_start = stmm_ns_comm_buf_addr;
	mmram_desc_data->region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	mmram_resv_data_size = sizeof(struct efi_mmram_hob_descriptor_block) +
			       sizeof(struct efi_mmram_descriptor) * 5;

	ret = efi_create_guid_hob(hob_table, &mmram_resv_guid,
				  mmram_resv_data_size, &guid_hob_data);
	if (ret) {
		EMSG("Failed to create mm range hob");
		return NULL;
	}

	mmram_resv_data = guid_hob_data;
	mmram_resv_data->number_of_mm_reserved_regions = 4;
	mmram_desc_data = &mmram_resv_data->descriptor[0];

	mmram_desc_data[0].physical_start = stmm_image_addr;
	mmram_desc_data[0].physical_size = uncompressed_size_roundup;
	mmram_desc_data[0].cpu_start = stmm_image_addr;
	mmram_desc_data[0].region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	mmram_desc_data[1].physical_start = stmm_sec_buf_addr;
	mmram_desc_data[1].physical_size = stmm_sec_buf_size;
	mmram_desc_data[1].cpu_start = stmm_sec_buf_addr;
	mmram_desc_data[1].region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	mmram_desc_data[2].physical_start = stmm_ns_comm_buf_addr;
	mmram_desc_data[2].physical_size = stmm_ns_comm_buf_size;
	mmram_desc_data[2].cpu_start = stmm_ns_comm_buf_addr;
	mmram_desc_data[2].region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	mmram_desc_data[3].physical_start = stmm_heap_addr;
	mmram_desc_data[3].physical_size = stmm_heap_size;
	mmram_desc_data[3].cpu_start = stmm_heap_addr;
	mmram_desc_data[3].region_state = EFI_CACHEABLE;

	*hob_table_size = hob_table->efi_free_memory_bottom -
			  (efi_physical_address_t)hob_table;

	return hob_table;
}

static TEE_Result load_stmm(struct stmm_ctx *spc)
{
	struct ffa_boot_info_header_1_1 *hdr = NULL;
	struct ffa_boot_info_1_1 *desc = NULL;
	struct efi_hob_handoff_info_table *hob_table = NULL;
	uint32_t hob_table_size = 0;
	vaddr_t sp_addr = 0;
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

	hob_table = build_stmm_boot_hob_list(sp_addr, sp_size, &hob_table_size);
	if (!hob_table)
		return TEE_ERROR_NO_DATA;

	hdr = (void *)stmm_sec_buf_addr;

	hdr->signature = FFA_BOOT_INFO_SIGNATURE;
	hdr->version = FFA_VERSION_1_2;
	hdr->desc_size = sizeof(struct ffa_boot_info_1_1);
	hdr->desc_count = 1;
	hdr->desc_offset = sizeof(struct ffa_boot_info_header_1_1);
	hdr->reserved = 0;
	hdr->blob_size = hdr->desc_size * hdr->desc_count + hdr->desc_offset;

	desc = (void *)(stmm_sec_buf_addr + hdr->desc_offset);

	memset(desc->name, 0, FFA_BOOT_INFO_NAME_LEN);
	desc->type = FFA_BOOT_INFO_TYPE_ID_HOB;
	desc->flags = FFA_BOOT_INFO_FLAG_NAME_FORMAT_UUID |
				    (FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR <<
				    FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT);
	desc->size = hob_table_size;
	desc->contents = (vaddr_t)hob_table;

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

	init_stmm_regs(spc, (unsigned long)hdr, 0, 0, 0, stmm_image_addr);

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

#ifdef ARM64
	spc->regs.x[0] = __FFA_MSG_SEND_DIRECT_REQ;
	spc->regs.x[1] = (stmm_pta_id << 16) | stmm_id;
	spc->regs.x[2] = FFA_PARAM_MBZ;
	spc->regs.x[3] = spc->ns_comm_buf_addr;
	spc->regs.x[4] = ns_buf_size;
	spc->regs.x[5] = 0;
	spc->regs.x[6] = 0;
	spc->regs.x[7] = 0;
#endif
#ifdef ARM32
	spc->regs.r0 = __FFA_MSG_SEND_DIRECT_REQ;
	spc->regs.r1 = (stmm_pta_id << 16) | stmm_id;
	spc->regs.r2 = FFA_PARAM_MBZ;
	spc->regs.r3 = spc->ns_comm_buf_addr;
	spc->regs.r4 = ns_buf_size;
	spc->regs.r5 = 0;
	spc->regs.r6 = 0;
	spc->regs.r7 = 0;
#endif

	ts_push_current_session(s);

	memcpy((void *)spc->ns_comm_buf_addr, va, ns_buf_size);

	res = stmm_enter_user_mode(spc);
	if (res)
		goto out_session;
	/*
	 * Copy the SPM response from secure partition back to the non-secure
	 * buffer of the client that called us.
	 */
#ifdef ARM64
	ta_sess->param->u[1].val.a = spc->regs.x[4];
#endif
#ifdef ARM32
	ta_sess->param->u[1].val.a = spc->regs.r4;
#endif

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

static void service_compose_direct_resp(struct thread_scall_regs *regs,
					uint32_t ret_val)
{
	uint16_t src_id = 0;
	uint16_t dst_id = 0;

	/* extract from request */
	src_id = (SVC_REGS_A1(regs) >> 16) & UINT16_MAX;
	dst_id = SVC_REGS_A1(regs) & UINT16_MAX;

	/* compose message */
	SVC_REGS_A0(regs) = __FFA_MSG_SEND_DIRECT_RESP;
	/* swap endpoint ids */
	SVC_REGS_A1(regs) = SHIFT_U32(dst_id, 16) | src_id;
	SVC_REGS_A2(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A3(regs) = ret_val;
	SVC_REGS_A4(regs) = 0;
	SVC_REGS_A5(regs) = 0;
	SVC_REGS_A6(regs) = 0;
	SVC_REGS_A7(regs) = 0;
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

static uint32_t tee2ffa_ret_val(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return FFA_OK;
	case TEE_ERROR_NOT_IMPLEMENTED:
	case TEE_ERROR_NOT_SUPPORTED:
		return FFA_NOT_SUPPORTED;
	case TEE_ERROR_OUT_OF_MEMORY:
		return FFA_NO_MEMORY;
	case TEE_ERROR_ACCESS_DENIED:
		return FFA_DENIED;
	case TEE_ERROR_NO_DATA:
		return FFA_NO_DATA;
	case TEE_ERROR_BAD_PARAMETERS:
	default:
		return FFA_INVALID_PARAMETERS;
	}
}

static void spm_eret_error(int32_t error_code, struct thread_scall_regs *regs)
{
	SVC_REGS_A0(regs) = FFA_ERROR;
	SVC_REGS_A1(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A2(regs) = error_code;
	SVC_REGS_A3(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A4(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A5(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A6(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A7(regs) = FFA_PARAM_MBZ;
}

#define FILENAME "EFI_VARS"
static void stmm_handle_storage_service(struct thread_scall_regs *regs)
{
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_SHARE_READ |
			 TEE_DATA_FLAG_SHARE_WRITE;
	uint32_t action = SVC_REGS_A3(regs);
	void *va = (void *)SVC_REGS_A4(regs);
	unsigned long len = SVC_REGS_A5(regs);
	unsigned long offset = SVC_REGS_A6(regs);
	char obj_id[] = FILENAME;
	size_t obj_id_len = strlen(obj_id);
	TEE_Result res = TEE_SUCCESS;
	uint32_t stmm_rc = STMM_RET_INVALID_PARAM;

	switch (action) {
	case __FFA_SVC_RPMB_READ:
		DMSG("RPMB read");
		res = sec_storage_obj_read(TEE_STORAGE_PRIVATE_RPMB, obj_id,
					   obj_id_len, va, len, offset, flags);
		stmm_rc = tee2ffa_ret_val(res);
		break;
	case __FFA_SVC_RPMB_WRITE:
		DMSG("RPMB write");
		res = sec_storage_obj_write(TEE_STORAGE_PRIVATE_RPMB, obj_id,
					    obj_id_len, va, len, offset, flags);
		stmm_rc = tee2ffa_ret_val(res);
		break;
	default:
		EMSG("Undefined service id %#"PRIx32, action);
		break;
	}

	service_compose_direct_resp(regs, stmm_rc);
}

static void spm_handle_direct_req(struct thread_scall_regs *regs)
{
	uint16_t dst_id = SVC_REGS_A1(regs) & UINT16_MAX;

	if (dst_id == ffa_storage_id) {
		stmm_handle_storage_service(regs);
	} else {
		EMSG("Undefined endpoint id %#"PRIx16, dst_id);
		spm_eret_error(STMM_RET_INVALID_PARAM, regs);
	}
}

static void spm_handle_get_mem_attr(struct thread_scall_regs *regs)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ts_session *sess = NULL;
	struct stmm_ctx *spc = NULL;
	uint16_t attrs = 0;
	uint16_t perm = 0;
	vaddr_t va = 0;
	uint32_t ffa_ret = FFA_INVALID_PARAMETERS;

	sess = ts_get_current_session();
	spc = to_stmm_ctx(sess->ctx);

	va = SVC_REGS_A1(regs);
	if (!va)
		goto err;

	res = vm_get_prot(&spc->uctx, va, SMALL_PAGE_SIZE, &attrs);
	if (res)
		goto err;

	if ((attrs & TEE_MATTR_URW) == TEE_MATTR_URW)
		perm |= FFA_MEM_PERM_RW;
	else if ((attrs & TEE_MATTR_UR) == TEE_MATTR_UR)
		perm |= FFA_MEM_PERM_RO;

	if (!(attrs & TEE_MATTR_UX))
		perm |= FFA_MEM_PERM_NX;

	SVC_REGS_A0(regs) = FFA_SUCCESS_32;
	SVC_REGS_A1(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A2(regs) = perm;
	SVC_REGS_A3(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A4(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A5(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A6(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A7(regs) = FFA_PARAM_MBZ;

	return;

err:
	spm_eret_error(ffa_ret, regs);
}

static void spm_handle_set_mem_attr(struct thread_scall_regs *regs)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct ts_session *sess = NULL;
	struct stmm_ctx *spc = NULL;
	uintptr_t va = SVC_REGS_A1(regs);
	uint32_t nr_pages = SVC_REGS_A2(regs);
	uint32_t perm = SVC_REGS_A3(regs);
	size_t sz = 0;
	uint32_t prot = 0;
	uint32_t ffa_ret = FFA_INVALID_PARAMETERS;

	if (!va || !nr_pages ||
	    MUL_OVERFLOW(nr_pages, SMALL_PAGE_SIZE, &sz) ||
	    (perm & FFA_MEM_PERM_RESERVED))
		goto err;

	sess = ts_get_current_session();
	spc = to_stmm_ctx(sess->ctx);

	if ((perm & FFA_MEM_PERM_DATA_PERM) == FFA_MEM_PERM_RO)
		prot |= TEE_MATTR_UR;
	else if ((perm & FFA_MEM_PERM_DATA_PERM) == FFA_MEM_PERM_RW)
		prot |= TEE_MATTR_URW;

	if ((perm & FFA_MEM_PERM_INSTRUCTION_PERM) != FFA_MEM_PERM_NX)
		prot |= TEE_MATTR_UX;

	res = vm_set_prot(&spc->uctx, va, sz, prot);
	if (res) {
		ffa_ret = FFA_DENIED;
		goto err;
	}

	SVC_REGS_A0(regs) = FFA_SUCCESS_32;
	SVC_REGS_A1(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A2(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A3(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A4(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A5(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A6(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A7(regs) = FFA_PARAM_MBZ;

	return;

err:
	spm_eret_error(ffa_ret, regs);
}

/* Return true if returning to SP, false if returning to caller */
static bool spm_handle_scall(struct thread_scall_regs *regs)
{
#ifdef ARM64
	uint64_t *a0 = &regs->x0;
#endif
#ifdef ARM32
	uint32_t *a0 = &regs->r0;
#endif

	switch (*a0) {
	case FFA_VERSION:
		DMSG("Received FFA version");
		*a0 = FFA_VERSION_1_2;
		return true;
	case FFA_ID_GET:
		DMSG("Received FFA ID GET");
		SVC_REGS_A0(regs) = FFA_SUCCESS_32;
		SVC_REGS_A2(regs) = stmm_id;
		return true;
	case FFA_MSG_WAIT:
		DMSG("Received FFA_MSG_WAIT");
		return_from_sp_helper(false, 0, regs);
		return false;
	case __FFA_MSG_SEND_DIRECT_RESP:
		DMSG("Received FFA direct response");
		return_from_sp_helper(false, 0, regs);
		return false;
	case __FFA_MSG_SEND_DIRECT_REQ:
		DMSG("Received FFA direct request");
		spm_handle_direct_req(regs);
		return true;
	case __FFA_MEM_PERM_GET:
		DMSG("Received FFA mem perm get");
		spm_handle_get_mem_attr(regs);
		return true;
	case __FFA_MEM_PERM_SET:
		DMSG("Received FFA mem perm set");
		spm_handle_set_mem_attr(regs);
		return true;
	case FFA_ERROR:
		EMSG("Received FFA error");
		return_from_sp_helper(true /*panic*/, 0xabcd, regs);
		return false;
	default:
		DMSG("Undefined syscall %#"PRIx32, (uint32_t)*a0);
		spm_eret_error(FFA_NOT_SUPPORTED, regs);
		return true;
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
