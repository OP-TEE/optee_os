// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.
 */

#include <efi/hob.h>
#include <ffa.h>
#include <inttypes.h>
#include <kernel/thread_private.h>
#include <mm/vm.h>
#include <string.h>
#include <trace.h>

#include "stmm_sp_ffa.h"

#define FFA_SVC_RPMB_READ	UINT32_C(0xC4000066)
#define FFA_SVC_RPMB_WRITE	UINT32_C(0xC4000067)
#define FFA_SVC_RPMB_READ_32	UINT32_C(0x84000066)
#define FFA_SVC_RPMB_WRITE_32	UINT32_C(0x84000067)

#ifdef ARM64
#define __FFA_SVC_RPMB_READ	FFA_SVC_RPMB_READ
#define __FFA_SVC_RPMB_WRITE	FFA_SVC_RPMB_WRITE
#define __FFA_MSG_SEND_DIRECT_RESP	FFA_MSG_SEND_DIRECT_RESP_64
#define __FFA_MSG_SEND_DIRECT_REQ	FFA_MSG_SEND_DIRECT_REQ_64
#define __FFA_MEM_PERM_GET	FFA_MEM_PERM_GET_64
#define __FFA_MEM_PERM_SET	FFA_MEM_PERM_SET_64
#endif
#ifdef ARM32
#define __FFA_SVC_RPMB_READ	FFA_SVC_RPMB_READ_32
#define __FFA_SVC_RPMB_WRITE	FFA_SVC_RPMB_WRITE_32
#define __FFA_MSG_SEND_DIRECT_RESP	FFA_MSG_SEND_DIRECT_RESP_32
#define __FFA_MSG_SEND_DIRECT_REQ	FFA_MSG_SEND_DIRECT_REQ_32
#define __FFA_MEM_PERM_GET	FFA_MEM_PERM_GET_32
#define __FFA_MEM_PERM_SET	FFA_MEM_PERM_SET_32
#endif

static TEE_UUID ns_buf_guid = MM_NS_BUFFER_GUID;
static TEE_UUID mmram_resv_guid = MM_PEI_MMRAM_MEMORY_RESERVE_GUID;
static const uint16_t stmm_id = 1U;
static const uint16_t ffa_storage_id = 4U;

void stmm_ffa_set_direct_req(struct thread_ctx_regs *regs, uint16_t src_id,
			     uint16_t dst_id, vaddr_t buf_addr,
			     unsigned long buf_size)
{
#ifdef ARM64
	regs->x[0] = __FFA_MSG_SEND_DIRECT_REQ;
	regs->x[1] = SHIFT_U32(src_id, 16) | dst_id;
	regs->x[2] = FFA_PARAM_MBZ;
	regs->x[3] = buf_addr;
	regs->x[4] = buf_size;
	regs->x[5] = 0;
	regs->x[6] = 0;
	regs->x[7] = 0;
#endif
#ifdef ARM32
	regs->r0 = __FFA_MSG_SEND_DIRECT_REQ;
	regs->r1 = SHIFT_U32(src_id, 16) | dst_id;
	regs->r2 = FFA_PARAM_MBZ;
	regs->r3 = buf_addr;
	regs->r4 = buf_size;
	regs->r5 = 0;
	regs->r6 = 0;
	regs->r7 = 0;
#endif
}

unsigned long
stmm_ffa_get_direct_resp_size(const struct thread_ctx_regs *regs)
{
#ifdef ARM64
	return regs->x[4];
#endif
#ifdef ARM32
	return regs->r4;
#endif
}

void stmm_ffa_get_storage_req(const struct thread_scall_regs *regs,
			      struct stmm_ffa_storage_req *req)
{
	uint32_t action = SVC_REGS_A3(regs);

	*req = (struct stmm_ffa_storage_req){
		.op = STMM_FFA_STORAGE_OP_INVALID,
		.data = (void *)SVC_REGS_A4(regs),
		.data_len = SVC_REGS_A5(regs),
		.offset = SVC_REGS_A6(regs),
	};

	switch (action) {
	case __FFA_SVC_RPMB_READ:
		req->op = STMM_FFA_STORAGE_OP_READ;
		break;
	case __FFA_SVC_RPMB_WRITE:
		req->op = STMM_FFA_STORAGE_OP_WRITE;
		break;
	default:
		EMSG("Undefined service id %#"PRIx32, action);
		break;
	}
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

void stmm_ffa_complete_storage(struct thread_scall_regs *regs, TEE_Result res)
{
	service_compose_direct_resp(regs, tee2ffa_ret_val(res));
}

static void spm_eret_error(int32_t error_code,
			   struct thread_scall_regs *regs)
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

static struct efi_hob_handoff_info_table *
build_stmm_boot_hob_list(const struct stmm_ffa_mem *mem,
			 uint32_t *hob_table_size)
{
	struct efi_hob_handoff_info_table *hob_table = NULL;
	struct efi_mmram_descriptor *mmram_desc_data = NULL;
	struct efi_mmram_hob_descriptor_block *mmram_resv_data = NULL;
	uint16_t mmram_resv_data_size = 0;
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint32_t hob_table_offset = 0;
	void *guid_hob_data = NULL;

	hob_table_offset = sizeof(struct ffa_boot_info_header_1_1) +
			   sizeof(struct ffa_boot_info_1_1);

	hob_table = efi_create_hob_list(mem->sp_addr, mem->sp_size,
					mem->sec_buf_addr + hob_table_offset,
					mem->sec_buf_size - hob_table_offset);
	if (!hob_table) {
		EMSG("Failed to create hob_table.");
		return NULL;
	}

	ret = efi_create_fv_hob(hob_table, mem->sp_addr,
				mem->image_region_size);
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
	mmram_desc_data->physical_start = mem->ns_comm_buf_addr;
	mmram_desc_data->physical_size = mem->ns_comm_buf_size;
	mmram_desc_data->cpu_start = mem->ns_comm_buf_addr;
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

	mmram_desc_data[0].physical_start = mem->image_addr;
	mmram_desc_data[0].physical_size = mem->image_region_size;
	mmram_desc_data[0].cpu_start = mem->image_addr;
	mmram_desc_data[0].region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	mmram_desc_data[1].physical_start = mem->sec_buf_addr;
	mmram_desc_data[1].physical_size = mem->sec_buf_size;
	mmram_desc_data[1].cpu_start = mem->sec_buf_addr;
	mmram_desc_data[1].region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	mmram_desc_data[2].physical_start = mem->ns_comm_buf_addr;
	mmram_desc_data[2].physical_size = mem->ns_comm_buf_size;
	mmram_desc_data[2].cpu_start = mem->ns_comm_buf_addr;
	mmram_desc_data[2].region_state = EFI_CACHEABLE | EFI_ALLOCATED;

	mmram_desc_data[3].physical_start = mem->heap_addr;
	mmram_desc_data[3].physical_size = mem->heap_size;
	mmram_desc_data[3].cpu_start = mem->heap_addr;
	mmram_desc_data[3].region_state = EFI_CACHEABLE;

	*hob_table_size = hob_table->efi_free_memory_bottom -
			  (efi_physical_address_t)hob_table;

	return hob_table;
}

TEE_Result stmm_ffa_init(const struct stmm_ffa_mem *mem,
			 unsigned long *boot_info)
{
	struct ffa_boot_info_header_1_1 *hdr = NULL;
	struct ffa_boot_info_1_1 *desc = NULL;
	struct efi_hob_handoff_info_table *hob_table = NULL;
	uint32_t hob_table_size = 0;

	hob_table = build_stmm_boot_hob_list(mem, &hob_table_size);
	if (!hob_table)
		return TEE_ERROR_NO_DATA;

	hdr = (void *)mem->sec_buf_addr;
	hdr->signature = FFA_BOOT_INFO_SIGNATURE;
	hdr->version = FFA_VERSION_1_2;
	hdr->desc_size = sizeof(struct ffa_boot_info_1_1);
	hdr->desc_count = 1;
	hdr->desc_offset = sizeof(struct ffa_boot_info_header_1_1);
	hdr->reserved = 0;
	hdr->blob_size = hdr->desc_size * hdr->desc_count + hdr->desc_offset;

	desc = (void *)(mem->sec_buf_addr + hdr->desc_offset);
	memset(desc->name, 0, FFA_BOOT_INFO_NAME_LEN);
	desc->type = FFA_BOOT_INFO_TYPE_ID_HOB;
	desc->flags = FFA_BOOT_INFO_FLAG_NAME_FORMAT_UUID |
		      (FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR <<
		       FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT);
	desc->size = hob_table_size;
	desc->contents = (vaddr_t)hob_table;

	*boot_info = (unsigned long)hdr;

	return TEE_SUCCESS;
}

static enum stmm_ffa_action
spm_handle_direct_req(struct thread_scall_regs *regs)
{
	uint16_t dst_id = SVC_REGS_A1(regs) & UINT16_MAX;

	if (dst_id == ffa_storage_id)
		return STMM_FFA_STORAGE;

	EMSG("Undefined endpoint id %#"PRIx16, dst_id);
	spm_eret_error(FFA_INVALID_PARAMETERS, regs);

	return STMM_FFA_RESUME;
}

static void spm_handle_get_mem_attr(struct user_mode_ctx *uctx,
				    struct thread_scall_regs *regs)
{
	uint16_t attrs = 0;
	uint16_t perm = 0;
	vaddr_t va = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	va = SVC_REGS_A1(regs);
	if (!va)
		goto err;

	res = vm_get_prot(uctx, va, SMALL_PAGE_SIZE, &attrs);
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
	spm_eret_error(FFA_INVALID_PARAMETERS, regs);
}

static void spm_handle_set_mem_attr(struct user_mode_ctx *uctx,
				    struct thread_scall_regs *regs)
{
	uintptr_t va = SVC_REGS_A1(regs);
	uint32_t nr_pages = SVC_REGS_A2(regs);
	uint32_t perm = SVC_REGS_A3(regs);
	size_t sz = 0;
	uint32_t prot = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!va || !nr_pages ||
	    MUL_OVERFLOW(nr_pages, SMALL_PAGE_SIZE, &sz) ||
	    (perm & FFA_MEM_PERM_RESERVED))
		goto err;

	if ((perm & FFA_MEM_PERM_DATA_PERM) == FFA_MEM_PERM_RO)
		prot |= TEE_MATTR_UR;
	else if ((perm & FFA_MEM_PERM_DATA_PERM) == FFA_MEM_PERM_RW)
		prot |= TEE_MATTR_URW;

	if ((perm & FFA_MEM_PERM_INSTRUCTION_PERM) != FFA_MEM_PERM_NX)
		prot |= TEE_MATTR_UX;

	res = vm_set_prot(uctx, va, sz, prot);
	if (res) {
		spm_eret_error(FFA_DENIED, regs);
		return;
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
	spm_eret_error(FFA_INVALID_PARAMETERS, regs);
}

enum stmm_ffa_action stmm_ffa_handle_scall(struct user_mode_ctx *uctx,
					   struct thread_scall_regs *regs)
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
		return STMM_FFA_RESUME;
	case FFA_ID_GET:
		DMSG("Received FFA ID GET");
		SVC_REGS_A0(regs) = FFA_SUCCESS_32;
		SVC_REGS_A2(regs) = stmm_id;
		return STMM_FFA_RESUME;
	case FFA_MSG_WAIT:
		DMSG("Received FFA_MSG_WAIT");
		return STMM_FFA_RETURN;
	case __FFA_MSG_SEND_DIRECT_RESP:
		DMSG("Received FFA direct response");
		return STMM_FFA_RETURN;
	case __FFA_MSG_SEND_DIRECT_REQ:
		DMSG("Received FFA direct request");
		return spm_handle_direct_req(regs);
	case __FFA_MEM_PERM_GET:
		DMSG("Received FFA mem perm get");
		spm_handle_get_mem_attr(uctx, regs);
		return STMM_FFA_RESUME;
	case __FFA_MEM_PERM_SET:
		DMSG("Received FFA mem perm set");
		spm_handle_set_mem_attr(uctx, regs);
		return STMM_FFA_RESUME;
	case FFA_ERROR:
		EMSG("Received FFA error");
		return STMM_FFA_PANIC;
	default:
		DMSG("Undefined syscall %#"PRIx32, (uint32_t)*a0);
		spm_eret_error(FFA_NOT_SUPPORTED, regs);
		return STMM_FFA_RESUME;
	}
}
