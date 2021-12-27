// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <gen-asm-defines.h>
#include <kernel/boot.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <types_ext.h>

DEFINES
{
	/* struct thread_core_local */
	DEFINE(THREAD_CORE_LOCAL_SIZE, sizeof(struct thread_core_local));

	/* struct thread_trap_local */
	DEFINE(RISCV_TFRAME_SP, offsetof(struct thread_trap_frame, sp));
	DEFINE(RISCV_TFRAME_RA, offsetof(struct thread_trap_frame, ra));
	DEFINE(RISCV_TFRAME_GP, offsetof(struct thread_trap_frame, gp));
	DEFINE(RISCV_TFRAME_TP, offsetof(struct thread_trap_frame, tp));
	DEFINE(RISCV_TFRAME_T0, offsetof(struct thread_trap_frame, t0));
	DEFINE(RISCV_TFRAME_T1, offsetof(struct thread_trap_frame, t1));
	DEFINE(RISCV_TFRAME_T2, offsetof(struct thread_trap_frame, t2));
	DEFINE(RISCV_TFRAME_A0, offsetof(struct thread_trap_frame, a0));
	DEFINE(RISCV_TFRAME_A1, offsetof(struct thread_trap_frame, a1));
	DEFINE(RISCV_TFRAME_A2, offsetof(struct thread_trap_frame, a2));
	DEFINE(RISCV_TFRAME_A3, offsetof(struct thread_trap_frame, a3));
	DEFINE(RISCV_TFRAME_A4, offsetof(struct thread_trap_frame, a4));
	DEFINE(RISCV_TFRAME_A5, offsetof(struct thread_trap_frame, a5));
	DEFINE(RISCV_TFRAME_A6, offsetof(struct thread_trap_frame, a6));
	DEFINE(RISCV_TFRAME_A7, offsetof(struct thread_trap_frame, a7));
	DEFINE(RISCV_TFRAME_T3, offsetof(struct thread_trap_frame, t3));
	DEFINE(RISCV_TFRAME_T4, offsetof(struct thread_trap_frame, t4));
	DEFINE(RISCV_TFRAME_T5, offsetof(struct thread_trap_frame, t5));
	DEFINE(RISCV_TFRAME_T6, offsetof(struct thread_trap_frame, t6));
	DEFINE(RISCV_TFRAME_EPC, offsetof(struct thread_trap_frame, epc));
	DEFINE(RISCV_TFRAME_STATUS, offsetof(struct thread_trap_frame, status));
	DEFINE(RISCV_TFRAME_SIZE, sizeof(struct thread_trap_frame));

	/* struct thread_ctx_regs */
	DEFINE(RISCV_CTX_REG_STATUS, offsetof(struct thread_ctx_regs, status));
	DEFINE(RISCV_CTX_REG_RA, offsetof(struct thread_ctx_regs, ra));
	DEFINE(RISCV_CTX_REG_SP, offsetof(struct thread_ctx_regs, sp));
	DEFINE(RISCV_CTX_REG_FP, offsetof(struct thread_ctx_regs, fp));
	DEFINE(RISCV_CTX_REG_A0, offsetof(struct thread_ctx_regs, a0));
	DEFINE(RISCV_CTX_REG_A1, offsetof(struct thread_ctx_regs, a1));
	DEFINE(RISCV_CTX_REG_A2, offsetof(struct thread_ctx_regs, a2));
	DEFINE(RISCV_CTX_REG_A3, offsetof(struct thread_ctx_regs, a3));
	DEFINE(RISCV_CTX_REG_A4, offsetof(struct thread_ctx_regs, a4));
	DEFINE(RISCV_CTX_REG_A5, offsetof(struct thread_ctx_regs, a5));
	DEFINE(RISCV_CTX_REG_A6, offsetof(struct thread_ctx_regs, a6));
	DEFINE(RISCV_CTX_REG_A7, offsetof(struct thread_ctx_regs, a7));
	DEFINE(RISCV_CTX_REGS_SIZE, sizeof(struct thread_ctx_regs));

	/* struct core_mmu_config */
	DEFINE(CORE_MMU_CONFIG_SIZE, sizeof(struct core_mmu_config));
	DEFINE(CORE_MMU_CONFIG_LOAD_OFFSET,
	       offsetof(struct core_mmu_config, load_offset));
}
