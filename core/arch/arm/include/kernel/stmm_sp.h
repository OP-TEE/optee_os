/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2020, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 */

#ifndef __KERNEL_STMM_SP_H
#define __KERNEL_STMM_SP_H

#include <assert.h>
#include <config.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/user_mode_ctx_struct.h>
#include <types_ext.h>
#include <util.h>

#define STMM_RET_SUCCESS		0
#define STMM_RET_NOT_SUPPORTED	        -1
#define STMM_RET_INVALID_PARAM	        -2
#define STMM_RET_DENIED		        -3
#define STMM_RET_NO_MEM		        -5

#define STMM_MEM_ATTR_ACCESS_MASK	U(0x3)
#define STMM_MEM_ATTR_ACCESS_NONE	U(0)
#define STMM_MEM_ATTR_ACCESS_RW		U(1)
#define STMM_MEM_ATTR_ACCESS_RO		U(3)
#define STMM_MEM_ATTR_EXEC_NEVER	BIT(2)
#define STMM_MEM_ATTR_EXEC		U(0)
#define STMM_MEM_ATTR_ALL		(STMM_MEM_ATTR_ACCESS_RW | \
					 STMM_MEM_ATTR_ACCESS_RO | \
					 STMM_MEM_ATTR_EXEC_NEVER)

/*
 * Used for EDK2 StMM communication. Since StMM can be launched on an arbitrary
 * address it uses these 2 syscalls to define the memory attributes for the
 * data and code segments after dispatching the binaries.
 *
 * FFA_SVC_MEMORY_ATTRIBUTES_SET_64/FFA_SVC_MEMORY_ATTRIBUTES_SET_32:
 *  - x4: base address
 *  - x5: number of pages
 *  - x6: attributes of the remapping (described above)
 *
 * FFA_SVC_MEMORY_ATTRIBUTES_GET_32/FFA_SVC_MEMORY_ATTRIBUTES_GET_64:
 *  - x4: base address, currently only a single page is requested.
 */
#define FFA_SVC_MEMORY_ATTRIBUTES_GET_64	UINT32_C(0xC4000064)
#define FFA_SVC_MEMORY_ATTRIBUTES_SET_64	UINT32_C(0xC4000065)

#define FFA_SVC_MEMORY_ATTRIBUTES_GET_32	UINT32_C(0x84000064)
#define FFA_SVC_MEMORY_ATTRIBUTES_SET_32	UINT32_C(0x84000065)

/*
 * We need to define the RPMB IDs formally, since the plan is
 * for them to be included in the FFA spec (for SP-to-SP future communication).
 * This is fine for now as it represents the internal contract between the
 * EDK2 RPMB driver and Secure Partition
 *
 * FFA_SVC_RPMB_WRITE/FFA_SVC_RPMB_WRITE_32:
 *  - x4: virtual address of the buffer to write in the device
 *  - x5: buffer byte length
 *  - x6: byte offset in the device
 * FFA_SVC_RPMB_READ/FFA_SVC_RPMB_READ_32:
 *  - x4: virtual address of the buffer were RPMB contents are copied
 *  - x5: buffer byte length to read
 *  - x6: byte offset in the device
 */
#define FFA_SVC_RPMB_READ		UINT32_C(0xC4000066)
#define FFA_SVC_RPMB_WRITE		UINT32_C(0xC4000067)

#define FFA_SVC_RPMB_READ_32		UINT32_C(0x84000066)
#define FFA_SVC_RPMB_WRITE_32		UINT32_C(0x84000067)

/* Param header types */
#define STMM_PARAM_EP			UINT8_C(0x01)
#define STMM_PARAM_IMAGE_BINARY		UINT8_C(0x02)
#define STMM_PARAM_BL31			UINT8_C(0x03)
#define STMM_PARAM_BL_LOAD_INFO		UINT8_C(0x04)
#define STMM_PARAM_BL_PARAMS		UINT8_C(0x05)
#define STMM_PARAM_PSCI_LIB_ARGS	UINT8_C(0x06)
#define STMM_PARAM_SP_IMAGE_BOOT_INFO	UINT8_C(0x07)

/* Param header version */
#define STMM_PARAM_VERSION_1		UINT8_C(0x01)
#define STMM_PARAM_VERSION_2		UINT8_C(0x02)

/*
 * This structure provides information on format used to describe
 * secure partition invocation parameters.
 */
struct stmm_param_header {
	uint8_t type;		/* type of the structure */
	uint8_t version;	/* version of this structure */
	uint16_t size;		/* size of this structure in bytes */
	uint32_t attr;		/* attributes: unused bits SBZ */
};

/*
 * Flags used by the stmm_mp_info structure to describe the
 * characteristics of a cpu. Only a single flag is defined at the moment to
 * indicate the primary cpu.
 */
#define MP_INFO_FLAG_PRIMARY_CPU	UINT32_C(0x00000001)

/*
 * This structure is used to provide information required to initialise a S-EL0
 * partition.
 */
struct stmm_mp_info {
	uint64_t mpidr;
	uint32_t linear_id;
	uint32_t flags;
};

struct stmm_boot_info {
	struct stmm_param_header	h;
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
	struct stmm_mp_info	*mp_info;
};

struct stmm_ctx {
	struct user_mode_ctx uctx;
	struct tee_ta_ctx ta_ctx;
	struct thread_ctx_regs regs;
	vaddr_t ns_comm_buf_addr;
	unsigned int ns_comm_buf_size;
	bool is_initializing;
};

extern const struct ts_ops stmm_sp_ops;

static inline bool is_stmm_ctx(struct ts_ctx *ctx __maybe_unused)
{
	return IS_ENABLED(CFG_WITH_STMM_SP) && ctx && ctx->ops == &stmm_sp_ops;
}

static inline struct stmm_ctx *to_stmm_ctx(struct ts_ctx *ctx)
{
	assert(is_stmm_ctx(ctx));
	return container_of(ctx, struct stmm_ctx, ta_ctx.ts_ctx);
}

#ifdef CFG_WITH_STMM_SP
TEE_Result stmm_init_session(const TEE_UUID *uuid,
			     struct tee_ta_session *s);
#else
static inline TEE_Result
stmm_init_session(const TEE_UUID *uuid __unused,
		  struct tee_ta_session *s __unused)
{
	return TEE_ERROR_ITEM_NOT_FOUND;
}
#endif

#endif /*__KERNEL_STMM_SP_H*/
