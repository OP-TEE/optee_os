// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.
 */

#include <inttypes.h>
#include <kernel/thread_private.h>
#include <trace.h>

#include "stmm_sp_ffa.h"

#define FFA_SVC_RPMB_READ	UINT32_C(0xC4000066)
#define FFA_SVC_RPMB_WRITE	UINT32_C(0xC4000067)
#define FFA_SVC_RPMB_READ_32	UINT32_C(0x84000066)
#define FFA_SVC_RPMB_WRITE_32	UINT32_C(0x84000067)

#ifdef ARM64
#define __FFA_SVC_RPMB_READ	FFA_SVC_RPMB_READ
#define __FFA_SVC_RPMB_WRITE	FFA_SVC_RPMB_WRITE
#endif
#ifdef ARM32
#define __FFA_SVC_RPMB_READ	FFA_SVC_RPMB_READ_32
#define __FFA_SVC_RPMB_WRITE	FFA_SVC_RPMB_WRITE_32
#endif

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

void stmm_ffa_compose_direct_resp(struct thread_scall_regs *regs,
				  uint32_t ret_val)
{
	uint16_t src_id = (SVC_REGS_A1(regs) >> 16) & UINT16_MAX;
	uint16_t dst_id = SVC_REGS_A1(regs) & UINT16_MAX;

	SVC_REGS_A0(regs) = __FFA_MSG_SEND_DIRECT_RESP;
	SVC_REGS_A1(regs) = SHIFT_U32(dst_id, 16) | src_id;
	SVC_REGS_A2(regs) = FFA_PARAM_MBZ;
	SVC_REGS_A3(regs) = ret_val;
	SVC_REGS_A4(regs) = 0;
	SVC_REGS_A5(regs) = 0;
	SVC_REGS_A6(regs) = 0;
	SVC_REGS_A7(regs) = 0;
}

void stmm_ffa_complete_storage(struct thread_scall_regs *regs,
			       uint32_t ret_val)
{
	stmm_ffa_compose_direct_resp(regs, ret_val);
}

void stmm_ffa_eret_error(int32_t error_code,
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
