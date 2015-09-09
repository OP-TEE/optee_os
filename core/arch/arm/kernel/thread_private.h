/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef THREAD_PRIVATE_H
#define THREAD_PRIVATE_H

#ifndef ASM

#include <mm/core_mmu.h>
#include <kernel/vfp.h>

enum thread_state {
	THREAD_STATE_FREE,
	THREAD_STATE_SUSPENDED,
	THREAD_STATE_ACTIVE,
};

#ifdef ARM32
struct thread_ctx_regs {
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r12;
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t svc_spsr;
	uint32_t svc_sp;
	uint32_t svc_lr;
	uint32_t pc;
	uint32_t cpsr;
};
#endif /*ARM32*/

#ifdef ARM64
struct thread_ctx_regs {
	uint64_t sp;
	uint64_t pc;
	uint64_t cpsr;
	uint64_t x[31];
};
#endif /*ARM64*/

#ifdef ARM64
struct thread_user_mode_rec {
	uint64_t exit_status0_ptr;
	uint64_t exit_status1_ptr;
	uint64_t x[31 - 19]; /* x19..x30 */
};
#endif /*ARM64*/

struct thread_ctx {
	struct thread_ctx_regs regs;
	enum thread_state state;
	vaddr_t stack_va_end;
	void *tsd;
	uint32_t hyp_clnt_id;
	uint32_t flags;
	struct core_mmu_user_map user_map;
	bool have_user_map;
#ifdef ARM64
	vaddr_t kern_sp;	/* Saved kernel SP during user TA execution */
#endif
	void *rpc_arg;
	paddr_t rpc_parg;
	struct mutex_head mutexes;
};

#ifdef ARM64
/*
 * struct thread_core_local need to have alignment suitable for a stack
 * pointer since SP_EL1 points to this
 */
#define THREAD_CORE_LOCAL_ALIGNED __aligned(16)
#else
#define THREAD_CORE_LOCAL_ALIGNED
#endif

struct thread_core_local {
	vaddr_t tmp_stack_va_end;
	int curr_thread;
#ifdef ARM64
	uint32_t flags;
	vaddr_t abt_stack_va_end;
	uint64_t x[8];
#endif
} THREAD_CORE_LOCAL_ALIGNED;

#endif /*ASM*/

#ifdef ARM64
#define THREAD_CTX_KERN_SP_OFFSET			\
		(THREAD_CTX_REGS_SIZE + (4 + 2 + 1) * 8)
#define THREAD_CTX_SIZE					\
		(THREAD_CTX_KERN_SP_OFFSET + 5 * 8)

#define THREAD_CTX_REGS_SP_OFFSET			(8 * 0)
#define THREAD_CTX_REGS_PC_OFFSET			(8 * 1)
#define THREAD_CTX_REGS_SPSR_OFFSET			(8 * 2)
#define THREAD_CTX_REGS_X_OFFSET(x)			(8 * (3 + (x)))
#define THREAD_CTX_REGS_SIZE			THREAD_CTX_REGS_X_OFFSET(31)

#define THREAD_CORE_LOCAL_TMP_STACK_VA_END_OFFSET	(8 * 0)
#define THREAD_CORE_LOCAL_CURR_THREAD_OFFSET		(8 * 1)
#define THREAD_CORE_LOCAL_FLAGS_OFFSET			(8 * 1 + 4)
#define THREAD_CORE_LOCAL_ABT_STACK_VA_END_OFFSET	(8 * 2)
#define THREAD_CORE_LOCAL_X_OFFSET(x)			(8 * (3 + (x)))
#define THREAD_CORE_LOCAL_SIZE			THREAD_CORE_LOCAL_X_OFFSET(9)

/* Describes the flags field of struct thread_core_local */
#define THREAD_CLF_SAVED_SHIFT				4
#define THREAD_CLF_CURR_SHIFT				0
#define THREAD_CLF_MASK					0xf
#define THREAD_CLF_TMP					(1 << 0)
#define THREAD_CLF_ABORT				(1 << 1)
#define THREAD_CLF_THREAD				(1 << 2)

#define THREAD_USER_MODE_REC_EXIT_STATUS0_PTR_OFFSET	(0)
#define THREAD_USER_MODE_REC_EXIT_STATUS1_PTR_OFFSET	(8 * 1)
#define THREAD_USER_MODE_REC_X_OFFSET(x)		(8 * (2 + (x) - 19))
#define THREAD_USER_MODE_REC_SIZE   THREAD_USER_MODE_REC_X_OFFSET(31)

#endif /*ARM64*/

#ifndef ASM
/*
 * Initializes VBAR for current CPU (called by thread_init_per_cpu()
 */
void thread_init_vbar(void);

/* Handles a stdcall, r0-r7 holds the parameters */
void thread_std_smc_entry(void);

void thread_handle_abort(uint32_t abort_type, struct thread_abort_regs *regs);

struct thread_core_local *thread_get_core_local(void);

/*
 * Resumes execution of currently active thread by restoring context and
 * jumping to the instruction where to continue execution.
 *
 * Arguments supplied by non-secure world will be copied into the saved
 * context of the current thread if THREAD_FLAGS_COPY_ARGS_ON_RETURN is set
 * in the flags field in the thread context.
 */
void thread_resume(struct thread_ctx_regs *regs);

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

/* Sets sp for irq mode */
void thread_set_irq_sp(vaddr_t sp);

/* Sets sp for fiq mode */
void thread_set_fiq_sp(vaddr_t sp);
#endif /*ARM32*/

/* Handles a fast SMC by dispatching it to the registered fast SMC handler */
void thread_handle_fast_smc(struct thread_smc_args *args);

/* Handles a std SMC by dispatching it to the registered std SMC handler */
void thread_handle_std_smc(struct thread_smc_args *args);

/*
 * Suspends current thread and temorarily exits to non-secure world.
 * This function returns later when non-secure world returns.
 *
 * The purpose of this function is to request services from non-secure
 * world.
 */
#define THREAD_RPC_NUM_ARGS     3
void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]);

/* Checks stack canaries */
void thread_check_canaries(void);

void __thread_std_smc_entry(struct thread_smc_args *args);

#endif /*ASM*/

#endif /*THREAD_PRIVATE_H*/
