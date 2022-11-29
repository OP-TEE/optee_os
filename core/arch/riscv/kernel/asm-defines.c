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
	DEFINE(THREAD_CORE_LOCAL_HART_ID,
	       offsetof(struct thread_core_local, hart_id));
	DEFINE(THREAD_CORE_LOCAL_TMP_STACK_VA_END,
	       offsetof(struct thread_core_local, tmp_stack_va_end));
	DEFINE(THREAD_CORE_LOCAL_CURR_THREAD,
	       offsetof(struct thread_core_local, curr_thread));
	DEFINE(THREAD_CORE_LOCAL_FLAGS,
	       offsetof(struct thread_core_local, flags));
	DEFINE(THREAD_CORE_LOCAL_ABT_STACK_VA_END,
	       offsetof(struct thread_core_local, abt_stack_va_end));

	DEFINE(STACK_TMP_GUARD, STACK_CANARY_SIZE / 2 + STACK_TMP_OFFS);

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

	/* struct thread_trap_regs */
	DEFINE(RISCV_TRAP_REG_SP, offsetof(struct thread_trap_regs, sp));
	DEFINE(RISCV_TRAP_REG_RA, offsetof(struct thread_trap_regs, ra));
	DEFINE(RISCV_TRAP_REG_GP, offsetof(struct thread_trap_regs, gp));
	DEFINE(RISCV_TRAP_REG_TP, offsetof(struct thread_trap_regs, tp));
	DEFINE(RISCV_TRAP_REG_T0, offsetof(struct thread_trap_regs, t0));
	DEFINE(RISCV_TRAP_REG_T1, offsetof(struct thread_trap_regs, t1));
	DEFINE(RISCV_TRAP_REG_T2, offsetof(struct thread_trap_regs, t2));
	DEFINE(RISCV_TRAP_REG_A0, offsetof(struct thread_trap_regs, a0));
	DEFINE(RISCV_TRAP_REG_A1, offsetof(struct thread_trap_regs, a1));
	DEFINE(RISCV_TRAP_REG_A2, offsetof(struct thread_trap_regs, a2));
	DEFINE(RISCV_TRAP_REG_A3, offsetof(struct thread_trap_regs, a3));
	DEFINE(RISCV_TRAP_REG_A4, offsetof(struct thread_trap_regs, a4));
	DEFINE(RISCV_TRAP_REG_A5, offsetof(struct thread_trap_regs, a5));
	DEFINE(RISCV_TRAP_REG_A6, offsetof(struct thread_trap_regs, a6));
	DEFINE(RISCV_TRAP_REG_A7, offsetof(struct thread_trap_regs, a7));
	DEFINE(RISCV_TRAP_REG_T3, offsetof(struct thread_trap_regs, t3));
	DEFINE(RISCV_TRAP_REG_T4, offsetof(struct thread_trap_regs, t4));
	DEFINE(RISCV_TRAP_REG_T5, offsetof(struct thread_trap_regs, t5));
	DEFINE(RISCV_TRAP_REG_T6, offsetof(struct thread_trap_regs, t6));
	DEFINE(RISCV_TRAP_REG_EPC, offsetof(struct thread_trap_regs, epc));
	DEFINE(RISCV_TRAP_REG_STATUS, offsetof(struct thread_trap_regs, status));
	DEFINE(RISCV_TRAP_REGS_SIZE, sizeof(struct thread_trap_regs));

	/* struct core_mmu_config */
	DEFINE(CORE_MMU_CONFIG_SIZE, sizeof(struct core_mmu_config));
	DEFINE(CORE_MMU_CONFIG_LOAD_OFFSET,
	       offsetof(struct core_mmu_config, load_offset));
	DEFINE(CORE_MMU_CONFIG_SATP,
	       offsetof(struct core_mmu_config, satp));
}
