// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.
 */

#include <efi/hob.h>
#include <ffa.h>
#include <kernel/thread_private.h>
#include <mm/vm.h>
#include <string.h>

#include "stmm_sp_ffa.h"

#ifdef ARM64
#define __FFA_MEM_PERM_GET	FFA_MEM_PERM_GET_64
#define __FFA_MEM_PERM_SET	FFA_MEM_PERM_SET_64
#endif
#ifdef ARM32
#define __FFA_MEM_PERM_GET	FFA_MEM_PERM_GET_32
#define __FFA_MEM_PERM_SET	FFA_MEM_PERM_SET_32
#endif

static TEE_UUID ns_buf_guid = MM_NS_BUFFER_GUID;
static TEE_UUID mmram_resv_guid = MM_PEI_MMRAM_MEMORY_RESERVE_GUID;
static const uint16_t stmm_id = 1U;
static const uint16_t ffa_storage_id = 4U;

unsigned int stmm_ffa_get_stack_size(void)
{
	return U(0);
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
			 struct stmm_ffa_init_regs *regs)
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

	regs->a0 = (unsigned long)hdr;

	return TEE_SUCCESS;
}

uint32_t stmm_ffa_storage_result(TEE_Result res)
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

static enum stmm_ffa_action
spm_handle_direct_req(struct thread_scall_regs *regs)
{
	uint16_t dst_id = SVC_REGS_A1(regs) & UINT16_MAX;

	if (dst_id == ffa_storage_id)
		return STMM_FFA_STORAGE;

	EMSG("Undefined endpoint id %#"PRIx16, dst_id);
	stmm_ffa_eret_error(FFA_INVALID_PARAMETERS, regs);

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
	stmm_ffa_eret_error(FFA_INVALID_PARAMETERS, regs);
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
		stmm_ffa_eret_error(FFA_DENIED, regs);
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
	stmm_ffa_eret_error(FFA_INVALID_PARAMETERS, regs);
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
		stmm_ffa_eret_error(FFA_NOT_SUPPORTED, regs);
		return STMM_FFA_RESUME;
	}
}
