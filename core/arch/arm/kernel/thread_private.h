/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef THREAD_PRIVATE_H
#define THREAD_PRIVATE_H

#ifndef __ASSEMBLER__

#include <mm/core_mmu.h>
#include <mm/pgt_cache.h>
#include <kernel/vfp.h>
#include <kernel/mutex.h>
#include <kernel/thread.h>

enum thread_state {
	THREAD_STATE_FREE,
	THREAD_STATE_SUSPENDED,
	THREAD_STATE_ACTIVE,
};

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

struct thread_ctx {
	struct thread_ctx_regs regs;
	enum thread_state state;
	vaddr_t stack_va_end;
	uint32_t flags;
	struct core_mmu_user_map user_map;
	bool have_user_map;
#ifdef ARM64
	vaddr_t kern_sp;	/* Saved kernel SP during user TA execution */
#endif
#ifdef CFG_WITH_VFP
	struct thread_vfp_state vfp_state;
#endif
	void *rpc_arg;
	struct mobj *rpc_mobj;
	struct thread_specific_data tsd;
};
#endif /*__ASSEMBLER__*/

#ifdef ARM64
#ifdef CFG_WITH_VFP
#define THREAD_VFP_STATE_SIZE				\
	(16 + (16 * 32 + 16) * 2 + 16)
#else
#define THREAD_VFP_STATE_SIZE				0
#endif
#endif /*ARM64*/

/* Describes the flags field of struct thread_core_local */
#define THREAD_CLF_SAVED_SHIFT			4
#define THREAD_CLF_CURR_SHIFT			0
#define THREAD_CLF_MASK				0xf
#define THREAD_CLF_TMP_SHIFT			0
#define THREAD_CLF_ABORT_SHIFT			1
#define THREAD_CLF_IRQ_SHIFT			2
#define THREAD_CLF_FIQ_SHIFT			3

#define THREAD_CLF_TMP				(1 << THREAD_CLF_TMP_SHIFT)
#define THREAD_CLF_ABORT			(1 << THREAD_CLF_ABORT_SHIFT)
#define THREAD_CLF_IRQ				(1 << THREAD_CLF_IRQ_SHIFT)
#define THREAD_CLF_FIQ				(1 << THREAD_CLF_FIQ_SHIFT)

#ifndef __ASSEMBLER__
extern const void *stack_tmp_export;
extern const uint32_t stack_tmp_stride;
extern struct thread_ctx threads[];
extern thread_pm_handler_t thread_cpu_on_handler_ptr;
extern thread_pm_handler_t thread_cpu_off_handler_ptr;
extern thread_pm_handler_t thread_cpu_suspend_handler_ptr;
extern thread_pm_handler_t thread_cpu_resume_handler_ptr;
extern thread_pm_handler_t thread_system_off_handler_ptr;
extern thread_pm_handler_t thread_system_reset_handler_ptr;


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
void thread_excp_vect_workaround(void);
void thread_excp_vect_workaround_a15(void);
void thread_excp_vect_end(void);

/*
 * Assembly function as the first function in a thread.  Handles a stdcall,
 * a0-a3 holds the parameters. Hands over to __thread_std_smc_entry() when
 * everything is set up and does some post processing once
 * __thread_std_smc_entry() returns.
 */
void thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);
uint32_t __thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2,
				uint32_t a3);


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
#endif /*ARM32*/

/* Checks stack canaries */
void thread_check_canaries(void);

void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);
void thread_resume_from_rpc(uint32_t thread_id, uint32_t a0, uint32_t a1,
			    uint32_t a2, uint32_t a3);
void thread_lock_global(void);
void thread_unlock_global(void);


/*
 * Suspends current thread and temorarily exits to non-secure world.
 * This function returns later when non-secure world returns.
 *
 * The purpose of this function is to request services from non-secure
 * world.
 */
#define THREAD_RPC_NUM_ARGS     4
void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]);

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

#endif /*__ASSEMBLER__*/

#endif /*THREAD_PRIVATE_H*/
