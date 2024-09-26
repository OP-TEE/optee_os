/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 */

#ifndef __KERNEL_THREAD_PRIVATE_ARCH_H
#define __KERNEL_THREAD_PRIVATE_ARCH_H

#ifndef __ASSEMBLER__

#include <kernel/thread.h>

#define STACK_TMP_OFFS		0

#if defined(__clang__) && !defined(__OPTIMIZE_SIZE__)
#define STACK_TMP_SIZE		(4096 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#else
#define STACK_TMP_SIZE		(2048 + STACK_TMP_OFFS + CFG_STACK_TMP_EXTRA)
#endif

#ifdef CFG_CORE_DEBUG_CHECK_STACKS
#define STACK_THREAD_SIZE	(10240 + CFG_STACK_THREAD_EXTRA)
#else
#define STACK_THREAD_SIZE	(8192 + CFG_STACK_THREAD_EXTRA)
#endif

#define STACK_ABT_SIZE		4096

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

#define THREAD_RPC_NUM_ARGS     4

#define	TRAP_MODE_KERNEL	0
#define	TRAP_MODE_USER		1

struct thread_user_mode_rec {
	unsigned long ctx_regs_ptr;
	unsigned long exit_status0_ptr;
	unsigned long exit_status1_ptr;
	unsigned long pad;
	/*
	 * x[] is used to save registers for user/kernel context-switching
	 * 0: ra
	 * 1-2: s0-s1
	 * 3-12: s2-s11
	 */
	unsigned long x[13];
};

extern long thread_user_kcode_offset;

void thread_native_interrupt_handler(struct thread_ctx_regs *regs,
				     unsigned long cause);
void thread_foreign_interrupt_handler(struct thread_ctx_regs *regs);

/*
 * Initializes TVEC for current hart. Called by thread_init_per_cpu()
 */
void thread_init_tvec(void);
void thread_trap_vect(void);
void thread_trap_vect_end(void);

void thread_return_to_udomain(unsigned long arg0, unsigned long arg1,
			      unsigned long arg2, unsigned long arg3,
			      unsigned long arg4, unsigned long arg5);

void __panic_at_abi_return(void);

/* Helper function to prepare CSR status for exception return */
unsigned long xstatus_for_xret(uint8_t pie, uint8_t pp);

/*
 * Assembly function as the first function in a thread.  Handles a stdcall,
 * a0-a3 holds the parameters. Hands over to __thread_std_abi_entry() when
 * everything is set up and does some post processing once
 * __thread_std_abi_entry() returns.
 */
void thread_std_abi_entry(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
uint32_t __thread_std_abi_entry(uint32_t a0, uint32_t a1, uint32_t a2,
				uint32_t a3, uint32_t a4, uint32_t a5);
/*
 * Called from assembly only, vector_fast_abi_entry(). Handles a fast ABI
 * by dispatching it to the registered fast ABI handler.
 */
void thread_handle_fast_abi(struct thread_abi_args *args);

/*
 * Called from assembly only, vector_std_abi_entry(). Handles a std ABI by
 * dispatching it to the registered std ABI handler.
 */
uint32_t thread_handle_std_abi(uint32_t a0, uint32_t a1, uint32_t a2,
			       uint32_t a3, uint32_t a4, uint32_t a5,
			       uint32_t a6, uint32_t a7);

/*
 * Private functions made available for thread_rv.S
 */
int thread_state_suspend(uint32_t flags, unsigned long status, vaddr_t pc);
void thread_resume(struct thread_ctx_regs *regs);
uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
				  uint32_t *exit_status0,
				  uint32_t *exit_status1);
void *thread_get_tmp_sp(void);
void thread_state_free(void);
struct thread_ctx_regs *thread_get_ctx_regs(void);
void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
void thread_resume_from_rpc(uint32_t thread_id, uint32_t a0, uint32_t a1,
			    uint32_t a2, uint32_t a3);
void thread_rpc_xstatus(uint32_t rv[THREAD_RPC_NUM_ARGS], unsigned long status);
void __thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]);

static inline void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS])
{
	__thread_rpc(rv);
}

void thread_scall_handler(struct thread_scall_regs *regs);

#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_PRIVATE_ARCH_H*/
