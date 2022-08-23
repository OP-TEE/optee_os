/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef __KERNEL_THREAD_PRIVATE_ARCH_H
#define __KERNEL_THREAD_PRIVATE_ARCH_H

#ifndef __ASSEMBLER__

#include <kernel/thread.h>
#include <kernel/vfp.h>
#include <sm/sm.h>

#ifdef CFG_WITH_ARM_TRUSTED_FW
#define STACK_TMP_OFFS		0
#else
#define STACK_TMP_OFFS		SM_STACK_TMP_RESERVE_SIZE
#endif

#ifdef ARM32
#ifdef CFG_CORE_SANITIZE_KADDRESS
#define STACK_TMP_SIZE		(3072 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#else
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#endif
#define STACK_THREAD_SIZE	(8192 + CFG_STACK_THREAD_EXTRA)

#if defined(CFG_CORE_SANITIZE_KADDRESS) || defined(__clang__) || \
	!defined(CFG_CRYPTO_WITH_CE)
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		2048
#endif

#endif /*ARM32*/

#ifdef ARM64
#if defined(__clang__) && !defined(__OPTIMIZE_SIZE__)
#define STACK_TMP_SIZE		(4096 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#else
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#endif
#define STACK_THREAD_SIZE	(8192 + CFG_STACK_THREAD_EXTRA)

#if TRACE_LEVEL > 0
#define STACK_ABT_SIZE		3072
#else
#define STACK_ABT_SIZE		1024
#endif
#endif /*ARM64*/

#ifdef CFG_CORE_DEBUG_CHECK_STACKS
/*
 * Extra space added to each stack in order to reliably detect and dump stack
 * overflows. Should cover the maximum expected overflow size caused by any C
 * function (say, 512 bytes; no function should have that much local variables),
 * plus the maximum stack space needed by __cyg_profile_func_exit(): about 1 KB,
 * a large part of which is used to print the call stack. Total: 1.5 KB.
 */
#define STACK_CHECK_EXTRA	1536
#else
#define STACK_CHECK_EXTRA	0
#endif

#ifdef ARM64
struct thread_user_mode_rec {
	uint64_t ctx_regs_ptr;
	uint64_t exit_status0_ptr;
	uint64_t exit_status1_ptr;
	uint64_t pad;
	uint64_t x[31 - 19]; /* x19..x30 */
};
#endif /*ARM64*/

#ifdef CFG_WITH_VFP
struct thread_vfp_state {
	bool ns_saved;
	bool sec_saved;
	bool sec_lazy_saved;
	struct vfp_state ns;
	struct vfp_state sec;
	struct thread_user_vfp_state *uvfp;
};

#endif /*CFG_WITH_VFP*/
#endif /*__ASSEMBLER__*/

#ifdef ARM64
#ifdef CFG_WITH_VFP
#define THREAD_VFP_STATE_SIZE				\
	(16 + (16 * 32 + 16) * 2 + 16)
#else
#define THREAD_VFP_STATE_SIZE				0
#endif
#endif /*ARM64*/

#ifndef __ASSEMBLER__

/*
 * During boot note the part of code and data that needs to be mapped while
 * in user mode. The provided address and size have to be page aligned.
 * Note that the code and data will be mapped at the lowest possible
 * addresses available for user space (see core_mmu_get_user_va_range()).
 */
extern long thread_user_kcode_offset;

/*
 * Initializes VBAR for current CPU (called by thread_init_per_cpu()
 */
void thread_init_vbar(vaddr_t addr);

void thread_excp_vect(void);
void thread_excp_vect_wa_spectre_v2(void);
void thread_excp_vect_wa_a15_spectre_v2(void);
void thread_excp_vect_wa_spectre_bhb(void);
void thread_excp_vect_end(void);

/*
 * Assembly function as the first function in a thread.  Handles a stdcall,
 * a0-a3 holds the parameters. Hands over to __thread_std_smc_entry() when
 * everything is set up and does some post processing once
 * __thread_std_smc_entry() returns.
 */
void thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
uint32_t __thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2,
				uint32_t a3, uint32_t a4, uint32_t a5);

void thread_sp_alloc_and_run(struct thread_smc_args *args);

/*
 * Resumes execution of currently active thread by restoring context and
 * jumping to the instruction where to continue execution.
 *
 * Arguments supplied by non-secure world will be copied into the saved
 * context of the current thread if THREAD_FLAGS_COPY_ARGS_ON_RETURN is set
 * in the flags field in the thread context.
 */
void thread_resume(struct thread_ctx_regs *regs);

uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
				  uint32_t *exit_status0,
				  uint32_t *exit_status1);

/*
 * Private functions made available for thread_asm.S
 */

/* Returns the temp stack for current CPU */
void *thread_get_tmp_sp(void);

/*
 * Marks the current thread as suspended. And updated the flags
 * for the thread context (see thread resume for use of flags).
 * Returns thread index of the thread that was suspended.
 */
int thread_state_suspend(uint32_t flags, uint32_t cpsr, vaddr_t pc);

/*
 * Marks the current thread as free.
 */
void thread_state_free(void);

/* Returns a pointer to the saved registers in current thread context. */
struct thread_ctx_regs *thread_get_ctx_regs(void);

#ifdef ARM32
/* Sets sp for abort mode */
void thread_set_abt_sp(vaddr_t sp);

/* Sets sp for undefined mode */
void thread_set_und_sp(vaddr_t sp);

/* Sets sp for irq mode */
void thread_set_irq_sp(vaddr_t sp);

/* Sets sp for fiq mode */
void thread_set_fiq_sp(vaddr_t sp);

/* Read usr_sp banked CPU register */
uint32_t thread_get_usr_sp(void);
#endif /*ARM32*/

void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
void thread_resume_from_rpc(uint32_t thread_id, uint32_t a0, uint32_t a1,
			    uint32_t a2, uint32_t a3);

/*
 * Suspends current thread and temorarily exits to non-secure world.
 * This function returns later when non-secure world returns.
 *
 * The purpose of this function is to request services from non-secure
 * world.
 */
#define THREAD_RPC_NUM_ARGS     4
#ifdef CFG_CORE_FFA
struct thread_rpc_arg {
	union {
		struct {
			uint32_t w1;
			uint32_t w4;
			uint32_t w5;
			uint32_t w6;
		} call;
		struct {
			uint32_t w4;
			uint32_t w5;
			uint32_t w6;
		} ret;
		uint32_t pad[THREAD_RPC_NUM_ARGS];
	};
};

void thread_rpc(struct thread_rpc_arg *rpc_arg);
#else
void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]);
#endif

/*
 * Called from assembly only, vector_fast_smc_entry(). Handles a fast SMC
 * by dispatching it to the registered fast SMC handler.
 */
void thread_handle_fast_smc(struct thread_smc_args *args);

/*
 * Called from assembly only, vector_std_smc_entry().  Handles a std SMC by
 * dispatching it to the registered std SMC handler.
 */
uint32_t thread_handle_std_smc(uint32_t a0, uint32_t a1, uint32_t a2,
			       uint32_t a3, uint32_t a4, uint32_t a5,
			       uint32_t a6, uint32_t a7);

/* Called from assembly only. Handles a SVC from user mode. */
void thread_svc_handler(struct thread_svc_regs *regs);

void thread_spmc_register_secondary_ep(vaddr_t ep);
#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_PRIVATE_ARCH_H*/
