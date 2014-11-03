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
#endif

#define THREAD_ID_0		0
#define THREAD_ABT_STACK	0xfffffffe
#define THREAD_TMP_STACK	0xffffffff

#ifndef ASM
extern uint32_t thread_vector_table[];

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


struct thread_abort_regs {
	uint32_t spsr;
	uint32_t pad;
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t ip;
	uint32_t lr;
};
typedef void (*thread_abort_handler_t)(uint32_t abort_type,
			struct thread_abort_regs *regs);
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
#endif /*ASM*/
/*
 * Correctness of these defines are asserted with COMPILE_TIME_ASSERT in
 * thread_init_handlers().
 */
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

#ifndef ASM
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
void thread_init_handlers(const struct thread_handlers *handlers);

/*
 * Sets the stacks to be used by the different threads. Use THREAD_ID_0 for
 * first stack, THREAD_ID_0 + 1 for the next and so on.
 *
 * If stack_id == THREAD_ID_TMP_STACK the temporary stack used by current
 * CPU is selected.
 * If stack_id == THREAD_ID_ABT_STACK the abort stack used by current CPU
 * is selected.
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
