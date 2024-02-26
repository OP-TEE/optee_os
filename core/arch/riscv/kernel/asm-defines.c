// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <gen-asm-defines.h>
#include <kernel/boot.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/core_mmu_arch.h>
#include <types_ext.h>

DEFINES
{
	/* struct thread_ctx */
	DEFINE(THREAD_CTX_KERN_SP, offsetof(struct thread_ctx, kern_sp));
	DEFINE(THREAD_CTX_STACK_VA_END, offsetof(struct thread_ctx,
						 stack_va_end));
	DEFINE(THREAD_CTX_SIZE, sizeof(struct thread_ctx));

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
	DEFINE(THREAD_CORE_LOCAL_X0, offsetof(struct thread_core_local, x[0]));
	DEFINE(THREAD_CORE_LOCAL_X1, offsetof(struct thread_core_local, x[1]));

	DEFINE(STACK_TMP_GUARD, STACK_CANARY_SIZE / 2 + STACK_TMP_OFFS);

	/* struct thread_ctx_regs */
	DEFINE(THREAD_CTX_REG_STATUS, offsetof(struct thread_ctx_regs, status));
	DEFINE(THREAD_CTX_REG_EPC, offsetof(struct thread_ctx_regs, epc));
	DEFINE(THREAD_CTX_REG_IE, offsetof(struct thread_ctx_regs, ie));
	DEFINE(THREAD_CTX_REG_RA, offsetof(struct thread_ctx_regs, ra));
	DEFINE(THREAD_CTX_REG_SP, offsetof(struct thread_ctx_regs, sp));
	DEFINE(THREAD_CTX_REG_T0, offsetof(struct thread_ctx_regs, t0));
	DEFINE(THREAD_CTX_REG_S0, offsetof(struct thread_ctx_regs, s0));
	DEFINE(THREAD_CTX_REG_A0, offsetof(struct thread_ctx_regs, a0));
	DEFINE(THREAD_CTX_REG_S2, offsetof(struct thread_ctx_regs, s2));
	DEFINE(THREAD_CTX_REG_T3, offsetof(struct thread_ctx_regs, t3));
	DEFINE(THREAD_CTX_REGS_SIZE, sizeof(struct thread_ctx_regs));

	/* struct thread_user_mode_rec */
	DEFINE(THREAD_USER_MODE_REC_CTX_REGS_PTR,
	       offsetof(struct thread_user_mode_rec, ctx_regs_ptr));
	DEFINE(THREAD_USER_MODE_REC_X1,
	       offsetof(struct thread_user_mode_rec, x[0]));
	DEFINE(THREAD_USER_MODE_REC_X4,
	       offsetof(struct thread_user_mode_rec, x[3]));
	DEFINE(THREAD_USER_MODE_REC_X8,
	       offsetof(struct thread_user_mode_rec, x[4]));
	DEFINE(THREAD_USER_MODE_REC_X18,
	       offsetof(struct thread_user_mode_rec, x[6]));
	DEFINE(THREAD_USER_MODE_REC_SIZE, sizeof(struct thread_user_mode_rec));

	/* struct thread_trap_regs */
	DEFINE(THREAD_TRAP_REG_SP, offsetof(struct thread_trap_regs, sp));
	DEFINE(THREAD_TRAP_REG_RA, offsetof(struct thread_trap_regs, ra));
	DEFINE(THREAD_TRAP_REG_GP, offsetof(struct thread_trap_regs, gp));
	DEFINE(THREAD_TRAP_REG_TP, offsetof(struct thread_trap_regs, tp));
	DEFINE(THREAD_TRAP_REG_T0, offsetof(struct thread_trap_regs, t0));
	DEFINE(THREAD_TRAP_REG_S0, offsetof(struct thread_trap_regs, s0));
	DEFINE(THREAD_TRAP_REG_A0, offsetof(struct thread_trap_regs, a0));
	DEFINE(THREAD_TRAP_REG_T3, offsetof(struct thread_trap_regs, t3));
	DEFINE(THREAD_TRAP_REG_EPC, offsetof(struct thread_trap_regs, epc));
	DEFINE(THREAD_TRAP_REG_STATUS,
	       offsetof(struct thread_trap_regs, status));
	DEFINE(THREAD_TRAP_REG_IE, offsetof(struct thread_trap_regs, ie));
	DEFINE(THREAD_TRAP_REGS_SIZE, sizeof(struct thread_trap_regs));

	/* struct thread_scall_regs */
	DEFINE(THREAD_SCALL_REG_STATUS,
	       offsetof(struct thread_scall_regs, status));
	DEFINE(THREAD_SCALL_REG_RA, offsetof(struct thread_scall_regs, ra));
	DEFINE(THREAD_SCALL_REG_SP, offsetof(struct thread_scall_regs, sp));
	DEFINE(THREAD_SCALL_REG_A0, offsetof(struct thread_scall_regs, a0));
	DEFINE(THREAD_SCALL_REGS_SIZE, sizeof(struct thread_scall_regs));

	/* struct core_mmu_config */
	DEFINE(CORE_MMU_CONFIG_SIZE, sizeof(struct core_mmu_config));
	DEFINE(CORE_MMU_CONFIG_SATP,
	       offsetof(struct core_mmu_config, satp[0]));
	DEFINE(CORE_MMU_CONFIG_SATP_SIZE, sizeof(unsigned long));

	/* struct thread_abi_args */
	DEFINE(THREAD_ABI_ARGS_A0, offsetof(struct thread_abi_args, a0));
	DEFINE(THREAD_ABI_ARGS_SIZE, sizeof(struct thread_abi_args));
}
