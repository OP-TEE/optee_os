/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2020, Linaro Limited
 * Copyright (c) 2020, Arm Limited.
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.
 */

#ifndef __STMM_SP_FFA_H
#define __STMM_SP_FFA_H

#include <ffa.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

struct thread_scall_regs;
struct thread_ctx_regs;
struct user_mode_ctx;

#ifdef ARM64
#define SVC_REGS_A0(_regs)	((_regs)->x0)
#define SVC_REGS_A1(_regs)	((_regs)->x1)
#define SVC_REGS_A2(_regs)	((_regs)->x2)
#define SVC_REGS_A3(_regs)	((_regs)->x3)
#define SVC_REGS_A4(_regs)	((_regs)->x4)
#define SVC_REGS_A5(_regs)	((_regs)->x5)
#define SVC_REGS_A6(_regs)	((_regs)->x6)
#define SVC_REGS_A7(_regs)	((_regs)->x7)
#define __FFA_MSG_SEND_DIRECT_RESP	FFA_MSG_SEND_DIRECT_RESP_64
#define __FFA_MSG_SEND_DIRECT_REQ	FFA_MSG_SEND_DIRECT_REQ_64
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
#define __FFA_MSG_SEND_DIRECT_RESP	FFA_MSG_SEND_DIRECT_RESP_32
#define __FFA_MSG_SEND_DIRECT_REQ	FFA_MSG_SEND_DIRECT_REQ_32
#endif

struct stmm_ffa_mem {
	vaddr_t sp_addr;
	unsigned int sp_size;
	vaddr_t image_addr;
	unsigned int image_size;
	unsigned int image_region_size;
	vaddr_t heap_addr;
	unsigned int heap_size;
	vaddr_t stack_addr;
	unsigned int stack_size;
	vaddr_t ns_comm_buf_addr;
	unsigned int ns_comm_buf_size;
	vaddr_t sec_buf_addr;
	unsigned int sec_buf_size;
};

struct stmm_ffa_init_regs {
	unsigned long a0;
	unsigned long a1;
	unsigned long sp;
};

enum stmm_ffa_action {
	STMM_FFA_RESUME,
	STMM_FFA_RETURN,
	STMM_FFA_STORAGE,
	STMM_FFA_PANIC,
};

enum stmm_ffa_storage_op {
	STMM_FFA_STORAGE_OP_INVALID,
	STMM_FFA_STORAGE_OP_READ,
	STMM_FFA_STORAGE_OP_WRITE,
};

struct stmm_ffa_storage_req {
	enum stmm_ffa_storage_op op;
	void *data;
	unsigned long data_len;
	unsigned long offset;
};

/* FF-A helpers shared by the StMM core and version backends. */
void stmm_ffa_set_direct_req(struct thread_ctx_regs *regs, uint16_t src_id,
			     uint16_t dst_id, vaddr_t buf_addr,
			     unsigned long buf_size);
unsigned long
stmm_ffa_get_direct_resp_size(const struct thread_ctx_regs *regs);
void stmm_ffa_get_storage_req(const struct thread_scall_regs *regs,
			      struct stmm_ffa_storage_req *req);
void stmm_ffa_compose_direct_resp(struct thread_scall_regs *regs,
				  uint32_t ret_val);
void stmm_ffa_complete_storage(struct thread_scall_regs *regs,
			       uint32_t ret_val);
void stmm_ffa_eret_error(int32_t error_code,
			 struct thread_scall_regs *regs);

/* Interface implemented by the selected FF-A version backend. */
unsigned int stmm_ffa_get_stack_size(void);

TEE_Result stmm_ffa_init(const struct stmm_ffa_mem *mem,
			 struct stmm_ffa_init_regs *regs);
enum stmm_ffa_action stmm_ffa_handle_scall(struct user_mode_ctx *uctx,
					   struct thread_scall_regs *regs);
uint32_t stmm_ffa_storage_result(TEE_Result res);

#endif /* __STMM_SP_FFA_H */
