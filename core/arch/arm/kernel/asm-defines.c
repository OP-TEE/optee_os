// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <gen-asm-defines.h>
#include <kernel/generic_boot.h>
#include <kernel/thread.h>
#include <sm/pm.h>
#include <sm/sm.h>
#include <types_ext.h>
#include "thread_private.h"

DEFINES
{
#ifdef ARM32
	DEFINE(SM_NSEC_CTX_R0, offsetof(struct sm_nsec_ctx, r0));
	DEFINE(SM_NSEC_CTX_R8, offsetof(struct sm_nsec_ctx, r8));
	DEFINE(SM_SEC_CTX_R0, offsetof(struct sm_sec_ctx, r0));
	DEFINE(SM_SEC_CTX_MON_LR, offsetof(struct sm_sec_ctx, mon_lr));
	DEFINE(SM_CTX_SEC_SIZE, sizeof(struct sm_sec_ctx));
	DEFINE(SM_CTX_SIZE, sizeof(struct sm_ctx));
	DEFINE(SM_CTX_NSEC, offsetof(struct sm_ctx, nsec));
	DEFINE(SM_CTX_SEC, offsetof(struct sm_ctx, sec));

	DEFINE(THREAD_VECTOR_TABLE_FIQ_ENTRY,
	       offsetof(struct thread_vector_table, fiq_entry));

	DEFINE(THREAD_SVC_REG_R0, offsetof(struct thread_svc_regs, r0));
	DEFINE(THREAD_SVC_REG_R5, offsetof(struct thread_svc_regs, r5));
	DEFINE(THREAD_SVC_REG_R6, offsetof(struct thread_svc_regs, r6));

	/* struct thread_ctx_regs */
	DEFINE(THREAD_CTX_REGS_USR_SP,
	       offsetof(struct thread_ctx_regs, usr_sp));
	DEFINE(THREAD_CTX_REGS_PC, offsetof(struct thread_ctx_regs, pc));
	DEFINE(THREAD_CTX_REGS_CPSR, offsetof(struct thread_ctx_regs, cpsr));

	/* struct thread_core_local */
	DEFINE(THREAD_CORE_LOCAL_R0, offsetof(struct thread_core_local, r[0]));
	DEFINE(THREAD_CORE_LOCAL_SM_PM_CTX_PHYS,
	       offsetof(struct thread_core_local, sm_pm_ctx_phys));
	DEFINE(THREAD_CORE_LOCAL_SIZE, sizeof(struct thread_core_local));

	DEFINE(SM_PM_CTX_SIZE, sizeof(struct sm_pm_ctx));
#endif /*ARM32*/

#ifdef ARM64
	DEFINE(THREAD_SMC_ARGS_X0, offsetof(struct thread_smc_args, a0));
	DEFINE(THREAD_SMC_ARGS_SIZE, sizeof(struct thread_smc_args));

	DEFINE(THREAD_SVC_REG_X0, offsetof(struct thread_svc_regs, x0));
	DEFINE(THREAD_SVC_REG_X2, offsetof(struct thread_svc_regs, x2));
	DEFINE(THREAD_SVC_REG_X5, offsetof(struct thread_svc_regs, x5));
	DEFINE(THREAD_SVC_REG_X6, offsetof(struct thread_svc_regs, x6));
	DEFINE(THREAD_SVC_REG_X30, offsetof(struct thread_svc_regs, x30));
	DEFINE(THREAD_SVC_REG_ELR, offsetof(struct thread_svc_regs, elr));
	DEFINE(THREAD_SVC_REG_SPSR, offsetof(struct thread_svc_regs, spsr));
	DEFINE(THREAD_SVC_REG_SP_EL0, offsetof(struct thread_svc_regs, sp_el0));
	DEFINE(THREAD_SVC_REG_SIZE, sizeof(struct thread_svc_regs));

	/* struct thread_abort_regs */
	DEFINE(THREAD_ABT_REG_X0, offsetof(struct thread_abort_regs, x0));
	DEFINE(THREAD_ABT_REG_X2, offsetof(struct thread_abort_regs, x2));
	DEFINE(THREAD_ABT_REG_X30, offsetof(struct thread_abort_regs, x30));
	DEFINE(THREAD_ABT_REG_SPSR, offsetof(struct thread_abort_regs, spsr));
	DEFINE(THREAD_ABT_REGS_SIZE, sizeof(struct thread_abort_regs));

	/* struct thread_ctx */
	DEFINE(THREAD_CTX_KERN_SP, offsetof(struct thread_ctx, kern_sp));
	DEFINE(THREAD_CTX_SIZE, sizeof(struct thread_ctx));

	/* struct thread_ctx_regs */
	DEFINE(THREAD_CTX_REGS_SP, offsetof(struct thread_ctx_regs, sp));
	DEFINE(THREAD_CTX_REGS_X0, offsetof(struct thread_ctx_regs, x[0]));
	DEFINE(THREAD_CTX_REGS_X1, offsetof(struct thread_ctx_regs, x[1]));
	DEFINE(THREAD_CTX_REGS_X2, offsetof(struct thread_ctx_regs, x[2]));
	DEFINE(THREAD_CTX_REGS_X4, offsetof(struct thread_ctx_regs, x[4]));
	DEFINE(THREAD_CTX_REGS_X19, offsetof(struct thread_ctx_regs, x[19]));

	/* struct thread_user_mode_rec */
	DEFINE(THREAD_USER_MODE_REC_CTX_REGS_PTR,
	       offsetof(struct thread_user_mode_rec, ctx_regs_ptr));
	DEFINE(THREAD_USER_MODE_REC_EXIT_STATUS0_PTR,
	       offsetof(struct thread_user_mode_rec, exit_status0_ptr));
	DEFINE(THREAD_USER_MODE_REC_X19,
	       offsetof(struct thread_user_mode_rec, x[0]));
	DEFINE(THREAD_USER_MODE_REC_SIZE, sizeof(struct thread_user_mode_rec));

	/* struct thread_core_local */
	DEFINE(THREAD_CORE_LOCAL_X0, offsetof(struct thread_core_local, x[0]));
	DEFINE(THREAD_CORE_LOCAL_X2, offsetof(struct thread_core_local, x[2]));
#endif /*ARM64*/

	/* struct thread_core_local */
	DEFINE(THREAD_CORE_LOCAL_TMP_STACK_VA_END,
		offsetof(struct thread_core_local, tmp_stack_va_end));
	DEFINE(THREAD_CORE_LOCAL_CURR_THREAD,
		offsetof(struct thread_core_local, curr_thread));
	DEFINE(THREAD_CORE_LOCAL_FLAGS,
		offsetof(struct thread_core_local, flags));
	DEFINE(THREAD_CORE_LOCAL_ABT_STACK_VA_END,
		offsetof(struct thread_core_local, abt_stack_va_end));

	/* struct core_mmu_config */
	DEFINE(CORE_MMU_CONFIG_SIZE, sizeof(struct core_mmu_config));
	DEFINE(CORE_MMU_CONFIG_LOAD_OFFSET,
	       offsetof(struct core_mmu_config, load_offset));

	/* struct boot_embdata */
	DEFINE(BOOT_EMBDATA_HASHES_OFFSET,
	       offsetof(struct boot_embdata, hashes_offset));
	DEFINE(BOOT_EMBDATA_HASHES_LEN,
	       offsetof(struct boot_embdata, hashes_len));
	DEFINE(BOOT_EMBDATA_RELOC_OFFSET,
	       offsetof(struct boot_embdata, reloc_offset));
	DEFINE(BOOT_EMBDATA_RELOC_LEN,
	       offsetof(struct boot_embdata, reloc_len));
}
