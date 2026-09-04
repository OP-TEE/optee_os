// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.
 */

#include <ffa.h>
#include <kernel/thread_private.h>
#include <mm/vm.h>

#include "stmm_sp_ffa.h"

#ifdef ARM64
#define __FFA_SVC_MEMORY_ATTRIBUTES_GET	FFA_SVC_MEMORY_ATTRIBUTES_GET_64
#define __FFA_SVC_MEMORY_ATTRIBUTES_SET	FFA_SVC_MEMORY_ATTRIBUTES_SET_64
#endif
#ifdef ARM32
#define __FFA_SVC_MEMORY_ATTRIBUTES_GET	FFA_SVC_MEMORY_ATTRIBUTES_GET_32
#define __FFA_SVC_MEMORY_ATTRIBUTES_SET	FFA_SVC_MEMORY_ATTRIBUTES_SET_32
#endif

#define STMM_RET_SUCCESS		0
#define STMM_RET_NOT_SUPPORTED		-1
#define STMM_RET_INVALID_PARAM		-2
#define STMM_RET_DENIED			-3
#define STMM_RET_NO_MEM			-5

#define STMM_MEM_ATTR_ACCESS_MASK	U(0x3)
#define STMM_MEM_ATTR_ACCESS_RW		U(1)
#define STMM_MEM_ATTR_ACCESS_RO		U(3)
#define STMM_MEM_ATTR_EXEC_NEVER	BIT(2)
#define STMM_MEM_ATTR_EXEC		U(0)
#define STMM_MEM_ATTR_ALL		(STMM_MEM_ATTR_ACCESS_RW | \
					 STMM_MEM_ATTR_ACCESS_RO | \
					 STMM_MEM_ATTR_EXEC_NEVER)

/*
 * Private memory-management calls used by the FF-A v1.1 StandaloneMm
 * integration.
 */
#define FFA_SVC_MEMORY_ATTRIBUTES_GET_64	UINT32_C(0xC4000064)
#define FFA_SVC_MEMORY_ATTRIBUTES_SET_64	UINT32_C(0xC4000065)
#define FFA_SVC_MEMORY_ATTRIBUTES_GET_32	UINT32_C(0x84000064)
#define FFA_SVC_MEMORY_ATTRIBUTES_SET_32	UINT32_C(0x84000065)

#define STMM_PARAM_SP_IMAGE_BOOT_INFO	UINT8_C(0x07)
#define STMM_PARAM_VERSION_1		UINT8_C(0x01)
#define MP_INFO_FLAG_PRIMARY_CPU	UINT32_C(0x00000001)

static const uint16_t mem_mgr_id = 3U;
static const uint16_t ffa_storage_id = 4U;

struct stmm_param_header {
	uint8_t type;
	uint8_t version;
	uint16_t size;
	uint32_t attr;
};

struct stmm_mp_info {
	uint64_t mpidr;
	uint32_t linear_id;
	uint32_t flags;
};

struct stmm_boot_info {
	struct stmm_param_header h;
	uint64_t sp_mem_base;
	uint64_t sp_mem_limit;
	uint64_t sp_image_base;
	uint64_t sp_stack_base;
	uint64_t sp_heap_base;
	uint64_t sp_ns_comm_buf_base;
	uint64_t sp_shared_buf_base;
	uint64_t sp_image_size;
	uint64_t sp_pcpu_stack_size;
	uint64_t sp_heap_size;
	uint64_t sp_ns_comm_buf_size;
	uint64_t sp_shared_buf_size;
	uint32_t num_sp_mem_regions;
	uint32_t num_cpus;
	struct stmm_mp_info *mp_info;
};

unsigned int stmm_ffa_get_stack_size(void)
{
	return 4 * SMALL_PAGE_SIZE;
}

TEE_Result stmm_ffa_init(const struct stmm_ffa_mem *mem,
			 struct stmm_ffa_init_regs *regs)
{
	struct stmm_boot_info *boot_info = NULL;
	struct stmm_mp_info *mp_info = NULL;

	boot_info = (struct stmm_boot_info *)mem->sec_buf_addr;
	mp_info = (struct stmm_mp_info *)(boot_info + 1);
	*boot_info = (struct stmm_boot_info){
		.h.type = STMM_PARAM_SP_IMAGE_BOOT_INFO,
		.h.version = STMM_PARAM_VERSION_1,
		.h.size = sizeof(*boot_info),
		.h.attr = 0,
		.sp_mem_base = mem->sp_addr,
		.sp_mem_limit = mem->sp_addr + mem->sp_size,
		.sp_image_base = mem->image_addr,
		.sp_stack_base = mem->stack_addr,
		.sp_heap_base = mem->heap_addr,
		.sp_ns_comm_buf_base = mem->ns_comm_buf_addr,
		.sp_shared_buf_base = mem->sec_buf_addr,
		.sp_image_size = mem->image_size,
		.sp_pcpu_stack_size = mem->stack_size,
		.sp_heap_size = mem->heap_size,
		.sp_ns_comm_buf_size = mem->ns_comm_buf_size,
		.sp_shared_buf_size = mem->sec_buf_size,
		.num_sp_mem_regions = 6,
		.num_cpus = 1,
		.mp_info = mp_info,
	};
	mp_info->mpidr = read_mpidr();
	mp_info->linear_id = 0;
	mp_info->flags = MP_INFO_FLAG_PRIMARY_CPU;

	regs->a0 = mem->sec_buf_addr;
	regs->a1 = (vaddr_t)(mp_info + 1) - mem->sec_buf_addr;
	regs->sp = mem->stack_addr + mem->stack_size;

	return TEE_SUCCESS;
}

static uint32_t sp_svc_get_mem_attr(struct user_mode_ctx *uctx, vaddr_t va)
{
	uint16_t attrs = 0;
	uint16_t perm = 0;
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	if (!va)
		return STMM_RET_DENIED;

	res = vm_get_prot(uctx, va, SMALL_PAGE_SIZE, &attrs);
	if (res)
		return STMM_RET_DENIED;

	if ((attrs & TEE_MATTR_URW) == TEE_MATTR_URW)
		perm |= STMM_MEM_ATTR_ACCESS_RW;
	else if ((attrs & TEE_MATTR_UR) == TEE_MATTR_UR)
		perm |= STMM_MEM_ATTR_ACCESS_RO;

	if (!(attrs & TEE_MATTR_UX))
		perm |= STMM_MEM_ATTR_EXEC_NEVER;

	return perm;
}

static int sp_svc_set_mem_attr(struct user_mode_ctx *uctx, vaddr_t va,
			       unsigned int nr_pages, uint32_t perm)
{
	size_t sz = 0;
	uint32_t prot = 0;
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	if (!va || !nr_pages || MUL_OVERFLOW(nr_pages, SMALL_PAGE_SIZE, &sz) ||
	    (perm & ~STMM_MEM_ATTR_ALL))
		return STMM_RET_INVALID_PARAM;

	if ((perm & STMM_MEM_ATTR_ACCESS_MASK) == STMM_MEM_ATTR_ACCESS_RO)
		prot |= TEE_MATTR_UR;
	else if ((perm & STMM_MEM_ATTR_ACCESS_MASK) == STMM_MEM_ATTR_ACCESS_RW)
		prot |= TEE_MATTR_URW;

	if ((perm & STMM_MEM_ATTR_EXEC_NEVER) == STMM_MEM_ATTR_EXEC)
		prot |= TEE_MATTR_UX;

	res = vm_set_prot(uctx, va, sz, prot);
	if (res)
		return STMM_RET_DENIED;

	return STMM_RET_SUCCESS;
}

static void stmm_handle_mem_mgr_service(struct user_mode_ctx *uctx,
					struct thread_scall_regs *regs)
{
	uint32_t action = SVC_REGS_A3(regs);
	uintptr_t va = SVC_REGS_A4(regs);
	uint32_t nr_pages = SVC_REGS_A5(regs);
	uint32_t perm = SVC_REGS_A6(regs);

	switch (action) {
	case __FFA_SVC_MEMORY_ATTRIBUTES_GET:
		stmm_ffa_compose_direct_resp(regs,
					     sp_svc_get_mem_attr(uctx, va));
		break;
	case __FFA_SVC_MEMORY_ATTRIBUTES_SET:
		stmm_ffa_compose_direct_resp(regs, sp_svc_set_mem_attr(uctx, va,
								       nr_pages,
								       perm));
		break;
	default:
		EMSG("Undefined service id %#"PRIx32, action);
		stmm_ffa_compose_direct_resp(regs, STMM_RET_INVALID_PARAM);
		break;
	}
}

uint32_t stmm_ffa_storage_result(TEE_Result res)
{
	switch (res) {
	case TEE_SUCCESS:
		return STMM_RET_SUCCESS;
	case TEE_ERROR_NOT_IMPLEMENTED:
	case TEE_ERROR_NOT_SUPPORTED:
		return STMM_RET_NOT_SUPPORTED;
	case TEE_ERROR_ACCESS_DENIED:
		return STMM_RET_DENIED;
	case TEE_ERROR_OUT_OF_MEMORY:
		return STMM_RET_NO_MEM;
	case TEE_ERROR_BAD_PARAMETERS:
	default:
		return STMM_RET_INVALID_PARAM;
	}
}

static enum stmm_ffa_action
spm_handle_direct_req(struct user_mode_ctx *uctx,
		      struct thread_scall_regs *regs)
{
	uint16_t dst_id = SVC_REGS_A1(regs) & UINT16_MAX;

	if (dst_id == mem_mgr_id) {
		stmm_handle_mem_mgr_service(uctx, regs);
		return STMM_FFA_RESUME;
	}

	if (dst_id == ffa_storage_id)
		return STMM_FFA_STORAGE;

	EMSG("Undefined endpoint id %#"PRIx16, dst_id);
	stmm_ffa_eret_error(STMM_RET_INVALID_PARAM, regs);

	return STMM_FFA_RESUME;
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
		*a0 = FFA_VERSION_1_1;
		return STMM_FFA_RESUME;
	case __FFA_MSG_SEND_DIRECT_RESP:
		DMSG("Received FFA direct response");
		return STMM_FFA_RETURN;
	case __FFA_MSG_SEND_DIRECT_REQ:
		DMSG("Received FFA direct request");
		return spm_handle_direct_req(uctx, regs);
	case FFA_ERROR:
		EMSG("Received FFA error");
		return STMM_FFA_PANIC;
	default:
		DMSG("Undefined syscall %#"PRIx32, (uint32_t)*a0);
		stmm_ffa_eret_error(FFA_NOT_SUPPORTED, regs);
		return STMM_FFA_RESUME;
	}
}
