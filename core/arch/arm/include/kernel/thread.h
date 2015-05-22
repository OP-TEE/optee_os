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

#ifndef KERNEL_THREAD_H
#define KERNEL_THREAD_H

#ifndef ASM
#include <types_ext.h>
#include <compiler.h>
#endif

#define THREAD_ID_0		0

#ifndef ASM
extern uint32_t thread_vector_table[];

#ifdef ARM32
struct thread_smc_args {
	uint32_t a0;	/* SMC function ID */
	uint32_t a1;	/* Parameter */
	uint32_t a2;	/* Parameter */
	uint32_t a3;	/* Thread ID when returning from RPC */
	uint32_t a4;	/* Not used */
	uint32_t a5;	/* Not used */
	uint32_t a6;	/* Not used */
	uint32_t a7;	/* Hypervisor Client ID */
};
#endif /*ARM32*/
#ifdef ARM64
struct thread_smc_args {
	uint64_t a0;	/* SMC function ID */
	uint64_t a1;	/* Parameter */
	uint64_t a2;	/* Parameter */
	uint64_t a3;	/* Thread ID when returning from RPC */
	uint64_t a4;	/* Not used */
	uint64_t a5;	/* Not used */
	uint64_t a6;	/* Not used */
	uint64_t a7;	/* Hypervisor Client ID */
};
#endif /*ARM64*/

#ifdef ARM32
struct thread_abort_regs {
	uint32_t usr_sp;
	uint32_t usr_lr;
	uint32_t pad;
	uint32_t spsr;
	uint32_t elr;
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
	uint32_t ip;
};
#endif /*ARM32*/
#ifdef ARM64
struct thread_abort_regs {
	uint64_t x0;	/* r0_usr */
	uint64_t x1;	/* r1_usr */
	uint64_t x2;	/* r2_usr */
	uint64_t x3;	/* r3_usr */
	uint64_t x4;	/* r4_usr */
	uint64_t x5;	/* r5_usr */
	uint64_t x6;	/* r6_usr */
	uint64_t x7;	/* r7_usr */
	uint64_t x8;	/* r8_usr */
	uint64_t x9;	/* r9_usr */
	uint64_t x10;	/* r10_usr */
	uint64_t x11;	/* r11_usr */
	uint64_t x12;	/* r12_usr */
	uint64_t x13;	/* r13/sp_usr */
	uint64_t x14;	/* r14/lr_usr */
	uint64_t x15;
	uint64_t x16;
	uint64_t x17;
	uint64_t x18;
	uint64_t x19;
	uint64_t x20;
	uint64_t x21;
	uint64_t x22;
	uint64_t x23;
	uint64_t x24;
	uint64_t x25;
	uint64_t x26;
	uint64_t x27;
	uint64_t x28;
	uint64_t x29;
	uint64_t x30;
	uint64_t elr;
	uint64_t spsr;
	uint64_t sp_el0;
};
#endif /*ARM64*/

#ifdef ARM32
struct thread_svc_regs {
	uint32_t spsr;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t lr;
};
#endif /*ARM32*/
#ifdef ARM64
struct thread_svc_regs {
	uint64_t elr;
	uint64_t spsr;
	uint64_t pad;
	uint64_t x0;	/* r0_usr */
	uint64_t x1;	/* r1_usr */
	uint64_t x2;	/* r2_usr */
	uint64_t x3;	/* r3_usr */
	uint64_t x4;	/* r4_usr */
	uint64_t x5;	/* r5_usr */
	uint64_t x6;	/* r6_usr */
	uint64_t x7;	/* r7_usr */
	uint64_t x8;	/* r8_usr */
	uint64_t x9;	/* r9_usr */
	uint64_t x10;	/* r10_usr */
	uint64_t x11;	/* r11_usr */
	uint64_t x12;	/* r12_usr */
	uint64_t x13;	/* r13/sp_usr */
	uint64_t x14;	/* r14/lr_usr */
} __aligned(16);
#endif /*ARM64*/
#endif /*ASM*/


/*
 * Correctness of these defines are asserted with COMPILE_TIME_ASSERT in
 * thread_init_handlers().
 */
#ifdef ARM32
#define THREAD_SVC_REG_SPSR_OFFS	(0 * 4)
#define THREAD_SVC_REG_R0_OFFS		(1 * 4)
#define THREAD_SVC_REG_R1_OFFS		(2 * 4)
#define THREAD_SVC_REG_R2_OFFS		(3 * 4)
#define THREAD_SVC_REG_R3_OFFS		(4 * 4)
#define THREAD_SVC_REG_R4_OFFS		(5 * 4)
#define THREAD_SVC_REG_R5_OFFS		(6 * 4)
#define THREAD_SVC_REG_R6_OFFS		(7 * 4)
#define THREAD_SVC_REG_R7_OFFS		(8 * 4)
#define THREAD_SVC_REG_LR_OFFS		(9 * 4)
#endif /*ARM32*/

#ifdef ARM64
#define THREAD_ABT_REG_X_OFFS(x)	((x) * 8)
#define THREAD_ABT_REG_ELR_OFFS		(THREAD_ABT_REG_X_OFFS(30) + 1 * 8)
#define THREAD_ABT_REG_SPSR_OFFS	(THREAD_ABT_REG_X_OFFS(30) + 2 * 8)
#define THREAD_ABT_REG_SP_EL0_OFFS	(THREAD_ABT_REG_X_OFFS(30) + 3 * 8)
#define THREAD_ABT_REGS_SIZE		(THREAD_ABT_REG_X_OFFS(30) + 4 * 8)

#define THREAD_SMC_ARGS_X_OFFS(x)	((x) * 8)
#define THREAD_SMC_ARGS_SIZE		THREAD_SMC_ARGS_X_OFFS(8)

#define THREAD_SVC_REG_ELR_OFFS		(8 * 0)
#define THREAD_SVC_REG_SPSR_OFFS	(8 * 1)
#define THREAD_SVC_REG_PAD_OFFS		(8 * 2)
#define THREAD_SVC_REG_X_OFFS(x)	(8 * (3 + (x)))
#define THREAD_SVC_REG_SIZE		THREAD_SVC_REG_X_OFFS(15)

#endif /*ARM64*/

#ifndef ASM
typedef void (*thread_abort_handler_t)(uint32_t abort_type,
			struct thread_abort_regs *regs);
typedef void (*thread_svc_handler_t)(struct thread_svc_regs *regs);
typedef void (*thread_smc_handler_t)(struct thread_smc_args *args);
typedef void (*thread_fiq_handler_t)(void);
typedef uint32_t (*thread_pm_handler_t)(uint32_t a0, uint32_t a1);
struct thread_handlers {
	/*
	 * stdcall and fastcall are called as regular functions and
	 * normal ARM Calling Convention applies. Return values are passed
	 * args->param{1-3} and forwarded into r0-r3 when returned to
	 * non-secure world.
	 *
	 * stdcall handles calls which can be preemted from non-secure
	 * world. This handler is executed with a large stack.
	 *
	 * fastcall handles fast calls which can't be preemted. This
	 * handler is executed with a limited stack. This handler must not
	 * cause any aborts or reenenable FIQs which are temporarily masked
	 * while executing this handler.
	 *
	 * TODO investigate if we should execute fastcalls and FIQs on
	 * different stacks allowing FIQs to be enabled during a fastcall.
	 */
	thread_smc_handler_t std_smc;
	thread_smc_handler_t fast_smc;

	/*
	 * fiq is called as a regular function and normal ARM Calling
	 * Convention applies.
	 *
	 * This handler handles FIQs which can't be preemted. This handler
	 * is executed with a limited stack. This handler must not cause
	 * any aborts or reenenable FIQs which are temporarily masked while
	 * executing this handler.
	 */
	thread_fiq_handler_t fiq;

	/*
	 * Power management handlers triggered from ARM Trusted Firmware.
	 * Not used when using internal monitor.
	 */
	thread_pm_handler_t cpu_on;
	thread_pm_handler_t cpu_off;
	thread_pm_handler_t cpu_suspend;
	thread_pm_handler_t cpu_resume;
	thread_pm_handler_t system_off;
	thread_pm_handler_t system_reset;


	/*
	 * The SVC handler is called as a normal function and should do
	 * a normal return. Note that IRQ is masked when this function
	 * is called, it's permitted for the function to unmask IRQ.
	 */
	thread_svc_handler_t svc;

	/*
	 * The abort handler is called as a normal function and should do
	 * a normal return. The abort handler is called when an undefined,
	 * prefetch abort, or data abort exception is received. In all
	 * cases the abort handler is executing in abort mode. If IRQ is
	 * unmasked in the abort handler it has to have separate abort
	 * stacks for each thread.
	 */
	thread_abort_handler_t abort;
};
void thread_init_primary(const struct thread_handlers *handlers);
void thread_init_per_cpu(void);

/*
 * Sets the stacks to be used by the different threads. Use THREAD_ID_0 for
 * first stack, THREAD_ID_0 + 1 for the next and so on.
 *
 * Returns true on success and false on errors.
 */
bool thread_init_stack(uint32_t stack_id, vaddr_t sp);

/*
 * Returns current thread id.
 */
uint32_t thread_get_id(void);

/*
 * Set Thread Specific Data (TSD) pointer.
 */
void thread_set_tsd(void *tsd);

/* Returns Thread Specific Data (TSD) pointer. */
void *thread_get_tsd(void);

/*
 * Sets IRQ status for current thread, must only be called from an
 * active thread context.
 *
 * enable == true  -> enable IRQ
 * enable == false -> disable IRQ
 */
void thread_set_irq(bool enable);

/*
 * Restores the IRQ status (in CPSR) for current thread, must only be called
 * from an active thread context.
 */
void thread_restore_irq(void);

/*
 * Defines the bits for the exception mask used the the
 * thread_*_exceptions() functions below.
 */
#define THREAD_EXCP_FIQ	(1 << 0)
#define THREAD_EXCP_IRQ	(1 << 1)
#define THREAD_EXCP_ABT	(1 << 2)
#define THREAD_EXCP_ALL	(THREAD_EXCP_FIQ | THREAD_EXCP_IRQ | THREAD_EXCP_ABT)

/*
 * thread_get_exceptions() - return current exception mask
 */
uint32_t thread_get_exceptions(void);

/*
 * thread_set_exceptions() - set exception mask
 * @exceptions: exception mask to set
 *
 * Any previous exception mask is replaced by this exception mask, that is,
 * old bits are cleared and replaced by these.
 */
void thread_set_exceptions(uint32_t exceptions);

/*
 * thread_mask_exceptions() - Masks (disables) specified asynchronous exceptions
 * @exceptions	exceptions to mask
 * @returns old exception state
 */
uint32_t thread_mask_exceptions(uint32_t exceptions);

/*
 * thread_unmask_exceptions() - Unmasks asynchronous exceptions
 * @state	Old asynchronous exception state to restore (returned by
 *		thread_mask_exceptions())
 */
void thread_unmask_exceptions(uint32_t state);

/*
 * thread_kernel_enable_vfp() - Temporarily enables usage of VFP
 *
 * IRQ is masked while VFP is enabled. User space must not be entered before
 * thread_kernel_disable_vfp() has been called to disable VFP and restore the
 * IRQ status.
 *
 * This function may only be called from an active thread context and may
 * not be called again before thread_kernel_disable_vfp() has been called.
 *
 * VFP state is saved as needed.
 *
 * Returns a state variable that should be passed to
 * thread_kernel_disable_vfp().
 */
uint32_t thread_kernel_enable_vfp(void);

/*
 * thread_kernel_disable_vfp() - Disables usage of VFP
 * @state:	state variable returned by thread_kernel_enable_vfp()
 *
 * Disables usage of VFP and restores IRQ status after a call to
 * thread_kernel_enable_vfp().
 *
 * This function may only be called after a call to
 * thread_kernel_enable_vfp().
 */
void thread_kernel_disable_vfp(uint32_t state);

/*
 * thread_enter_user_mode() - Enters user mode
 * @a0:		Passed in r/x0 for user_func
 * @a1:		Passed in r/x1 for user_func
 * @a2:		Passed in r/x2 for user_func
 * @a3:		Passed in r/x3 for user_func
 * @user_sp:	Assigned sp value in user mode
 * @user_func:	Function to execute in user mode
 * @exit_status0: Pointer to opaque exit staus 0
 * @exit_status1: Pointer to opaque exit staus 1
 *
 * This functions enters user mode with the argument described above,
 * @exit_status0 and @exit_status1 are filled in by thread_unwind_user_mode()
 * when returning back to the caller of this function through an exception
 * handler.
 *
 * @Returns what's passed in "ret" to thread_unwind_user_mode()
 */

uint32_t thread_enter_user_mode(uint32_t a0, uint32_t a1, uint32_t a2,
		uint32_t a3, vaddr_t user_sp, vaddr_t user_func,
		uint32_t *exit_status0, uint32_t *exit_status1);

/*
 * thread_unwind_user_mode() - Unwinds kernel stack from user entry
 * @ret:	Value to return from thread_enter_user_mode()
 * @exit_status0: Exit status 0
 * @exit_status1: Exit status 1
 *
 * This is the function that exception handlers can return into
 * to resume execution in kernel mode instead of user mode.
 *
 * This function is closely coupled with thread_enter_user_mode() since it
 * need to restore registers saved by thread_enter_user_mode() and when it
 * returns make it look like thread_enter_user_mode() just returned. It is
 * expected that the stack pointer is where thread_enter_user_mode() left
 * it. The stack will be unwound and the function will return to where
 * thread_enter_user_mode() was called from.  Exit_status0 and exit_status1
 * are filled in the corresponding pointers supplied to
 * thread_enter_user_mode().
 */
void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
		uint32_t exit_status1);

#ifdef ARM64
/*
 * thread_get_saved_thread_sp() - Returns the saved sp of current thread
 *
 * When switching from the thread stack pointer the value is stored
 * separately in the current thread context. This function returns this
 * saved value.
 *
 * @returns stack pointer
 */
vaddr_t thread_get_saved_thread_sp(void);
#endif /*ARM64*/

/**
 * Allocates data for struct teesmc32_arg.
 *
 * @size: size in bytes of struct teesmc32_arg
 *
 * @returns 0 on failure or a physical pointer to a struct teesmc32_arg buffer
 *          on success.
 */
paddr_t thread_rpc_alloc_arg(size_t size);

/**
 * Allocates data for a payload buffer.
 *
 * @size: size in bytes of payload buffer
 *
 * @returns 0 on failure or a physical pointer to a payload buffer on success.
 */
paddr_t thread_rpc_alloc_payload(size_t size);

/**
 * Free physical memory previously allocated with thread_rpc_alloc_arg()
 *
 * @arg: physical pointer to struct teesmc32_arg buffer
 */
void thread_rpc_free_arg(paddr_t arg);

/**
 * Free physical memory previously allocated with thread_rpc_alloc_payload()
 *
 * @arg: physical pointer to struct teesmc32_arg buffer
 */
void thread_rpc_free_payload(paddr_t payload);

/**
 * Does an RPC with a physical pointer to a struct teesmc32_arg
 *
 * @arg: physical pointer to struct teesmc32_arg
 */
void thread_rpc_cmd(paddr_t arg);

/**
 * Extension: Allocates data for payload buffers.
 *
 * @size: size in bytes of payload buffer
 * @payload: returned physcial pointer to payload buffer
 * @cookie: returned cookie used when freeing the buffer
 */
void thread_optee_rpc_alloc_payload(size_t size, paddr_t *payload,
				 paddr_t *cookie);

/**
 * Extension: Free physical memory previously allocated with thread_rpc_alloc()
 *
 * @cookie: cookie received when allocating the payload buffer
 */
void thread_optee_rpc_free_payload(paddr_t cookie);

#endif /*ASM*/

#endif /*KERNEL_THREAD_H*/
