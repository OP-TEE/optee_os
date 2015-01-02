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
#include <platform_config.h>

#include <kernel/thread.h>
#include <kernel/thread_defs.h>
#include "thread_private.h"
#include <sm/teesmc.h>
#include <sm/teesmc_optee.h>
#include <arm32.h>
#include <kernel/arch_debug.h>
#include <kernel/tz_proc_def.h>
#include <kernel/tz_proc.h>
#include <kernel/misc.h>
#include <mm/tee_mmu.h>
#include <kernel/tee_ta_manager.h>
#include <trace.h>

#include <assert.h>

static struct thread_ctx threads[NUM_THREADS];

static struct thread_core_local thread_core_local[CFG_TEE_CORE_NB_CORE];

#ifdef CFG_WITH_VFP
struct thread_vfp_state {
	bool ns_saved;
	bool sec_saved;
	bool sec_lazy_saved;
	struct vfp_state ns;
	struct vfp_state sec;
};

static struct thread_vfp_state thread_vfp_state;
#endif /*CFG_WITH_VFP*/

thread_smc_handler_t thread_std_smc_handler_ptr;
static thread_smc_handler_t thread_fast_smc_handler_ptr;
thread_fiq_handler_t thread_fiq_handler_ptr;
thread_svc_handler_t thread_svc_handler_ptr;
static thread_abort_handler_t thread_abort_handler_ptr;
thread_pm_handler_t thread_cpu_on_handler_ptr;
thread_pm_handler_t thread_cpu_off_handler_ptr;
thread_pm_handler_t thread_cpu_suspend_handler_ptr;
thread_pm_handler_t thread_cpu_resume_handler_ptr;
thread_pm_handler_t thread_system_off_handler_ptr;
thread_pm_handler_t thread_system_reset_handler_ptr;


static unsigned int thread_global_lock = UNLOCK;

static void lock_global(void)
{
	cpu_spin_lock(&thread_global_lock);
}

static void unlock_global(void)
{
	cpu_spin_unlock(&thread_global_lock);
}

static struct thread_core_local *get_core_local(void)
{
	uint32_t cpu_id = get_core_pos();

	/*
	 * IRQs must be disabled before playing with core_local since
	 * we otherwhise may be rescheduled to a different core in the
	 * middle of this function.
	 */
	assert(read_cpsr() & CPSR_I);

	assert(cpu_id < CFG_TEE_CORE_NB_CORE);
	return &thread_core_local[cpu_id];
}

static bool have_one_active_thread(void)
{
	size_t n;

	for (n = 0; n < NUM_THREADS; n++) {
		if (threads[n].state == THREAD_STATE_ACTIVE)
			return true;
	}

	return false;
}

static bool have_one_preempted_thread(void)
{
	size_t n;

	for (n = 0; n < NUM_THREADS; n++) {
		if (threads[n].state == THREAD_STATE_SUSPENDED &&
		    (threads[n].flags & THREAD_FLAGS_EXIT_ON_IRQ))
			return true;
	}

	return false;
}

#ifdef CFG_WITH_VFP
static void thread_lazy_save_ns_vfp(void)
{
	thread_vfp_state.ns_saved = false;
	vfp_lazy_save_state_init(&thread_vfp_state.ns);
}

static void thread_lazy_restore_ns_vfp(void)
{
	assert(!thread_vfp_state.sec_lazy_saved && !thread_vfp_state.sec_saved);
	vfp_lazy_restore_state(&thread_vfp_state.ns, thread_vfp_state.ns_saved);
	thread_vfp_state.ns_saved = false;
}
#else
static void thread_lazy_save_ns_vfp(void)
{
}

static void thread_lazy_restore_ns_vfp(void)
{
}
#endif /*CFG_WITH_VFP*/

static void thread_alloc_and_run(struct thread_smc_args *args)
{
	size_t n;
	struct thread_core_local *l = get_core_local();
	bool found_thread = false;

	assert(l->curr_thread == -1);

	lock_global();

	if (!have_one_active_thread() && !have_one_preempted_thread()) {
		for (n = 0; n < NUM_THREADS; n++) {
			if (threads[n].state == THREAD_STATE_FREE) {
				threads[n].state = THREAD_STATE_ACTIVE;
				found_thread = true;
				break;
			}
		}
	}

	unlock_global();

	if (!found_thread) {
		args->a0 = TEESMC_RETURN_EBUSY;
		return;
	}

	l->curr_thread = n;

	threads[n].regs.pc = (uint32_t)thread_std_smc_entry;
	/*
	 * Stdcalls starts in SVC mode with masked IRQ, masked Asynchronous
	 * abort and unmasked FIQ.
	  */
	threads[n].regs.cpsr = CPSR_MODE_SVC | CPSR_I | CPSR_A;
	threads[n].flags = 0;
	/* Enable thumb mode if it's a thumb instruction */
	if (threads[n].regs.pc & 1)
		threads[n].regs.cpsr |= CPSR_T;
	/* Reinitialize stack pointer */
	threads[n].regs.svc_sp = threads[n].stack_va_end;

	/*
	 * Copy arguments into context. This will make the
	 * arguments appear in r0-r7 when thread is started.
	 */
	threads[n].regs.r0 = args->a0;
	threads[n].regs.r1 = args->a1;
	threads[n].regs.r2 = args->a2;
	threads[n].regs.r3 = args->a3;
	threads[n].regs.r4 = args->a4;
	threads[n].regs.r5 = args->a5;
	threads[n].regs.r6 = args->a6;
	threads[n].regs.r7 = args->a7;

	/* Save Hypervisor Client ID */
	threads[n].hyp_clnt_id = args->a7;

	thread_lazy_save_ns_vfp();
	thread_resume(&threads[n].regs);
}

static void thread_resume_from_rpc(struct thread_smc_args *args)
{
	size_t n = args->a3; /* thread id */
	struct thread_core_local *l = get_core_local();
	uint32_t rv = 0;

	assert(l->curr_thread == -1);

	lock_global();

	if (have_one_active_thread()) {
		rv = TEESMC_RETURN_EBUSY;
	} else if (n < NUM_THREADS &&
		threads[n].state == THREAD_STATE_SUSPENDED &&
		args->a7 == threads[n].hyp_clnt_id) {
		/*
		 * If there's one preempted thread it has to be the one
		 * we're resuming.
		 */
		if (have_one_preempted_thread()) {
			if (threads[n].flags & THREAD_FLAGS_EXIT_ON_IRQ) {
				threads[n].flags &= ~THREAD_FLAGS_EXIT_ON_IRQ;
				threads[n].state = THREAD_STATE_ACTIVE;
			} else {
				rv = TEESMC_RETURN_EBUSY;
			}
		} else {
			threads[n].state = THREAD_STATE_ACTIVE;
		}
	} else {
		rv = TEESMC_RETURN_ERESUME;
	}

	unlock_global();

	if (rv) {
		args->a0 = rv;
		return;
	}

	l->curr_thread = n;

	if (threads[n].have_user_map)
		core_mmu_set_user_map(&threads[n].user_map);

	/*
	 * Return from RPC to request service of an IRQ must not
	 * get parameters from non-secure world.
	 */
	if (threads[n].flags & THREAD_FLAGS_COPY_ARGS_ON_RETURN) {
		/*
		 * Update returned values from RPC, values will appear in
		 * r0-r3 when thread is resumed.
		 */
		threads[n].regs.r0 = args->a0;
		threads[n].regs.r1 = args->a1;
		threads[n].regs.r2 = args->a2;
		threads[n].regs.r3 = args->a3;
		threads[n].flags &= ~THREAD_FLAGS_COPY_ARGS_ON_RETURN;
	}

	thread_lazy_save_ns_vfp();
	thread_resume(&threads[n].regs);
}

void thread_handle_fast_smc(struct thread_smc_args *args)
{
	check_canaries();
	thread_fast_smc_handler_ptr(args);
	/* Fast handlers must not clear F, I or A bits in CPSR */
	assert((read_cpsr() & CPSR_FIA) == CPSR_FIA);
}

void thread_handle_std_smc(struct thread_smc_args *args)
{
	check_canaries();

	if (args->a0 == TEESMC32_CALL_RETURN_FROM_RPC)
		thread_resume_from_rpc(args);
	else
		thread_alloc_and_run(args);
}

void thread_handle_abort(uint32_t abort_type, struct thread_abort_regs *regs)
{
#ifdef CFG_WITH_VFP
	if (vfp_is_enabled()) {
		vfp_lazy_save_state_init(&thread_vfp_state.sec);
		thread_vfp_state.sec_lazy_saved = true;
	}
#endif

	thread_abort_handler_ptr(abort_type, regs);

#ifdef CFG_WITH_VFP
	assert(!vfp_is_enabled());
	if (thread_vfp_state.sec_lazy_saved) {
		vfp_lazy_restore_state(&thread_vfp_state.sec,
				       thread_vfp_state.sec_saved);
		thread_vfp_state.sec_saved = false;
		thread_vfp_state.sec_lazy_saved = false;
	}
#endif
}

void *thread_get_tmp_sp(void)
{
	struct thread_core_local *l = get_core_local();

	return (void *)l->tmp_stack_va_end;
}

void thread_state_free(void)
{
	struct thread_core_local *l = get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);

	thread_lazy_restore_ns_vfp();

	lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].state = THREAD_STATE_FREE;
	threads[ct].flags = 0;
	l->curr_thread = -1;

	unlock_global();
}

int thread_state_suspend(uint32_t flags, uint32_t cpsr, uint32_t pc)
{
	struct thread_core_local *l = get_core_local();
	int ct = l->curr_thread;

	assert(ct != -1);

	check_canaries();

	thread_lazy_restore_ns_vfp();

	lock_global();

	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].flags |= flags;
	threads[ct].regs.cpsr = cpsr;
	threads[ct].regs.pc = pc;
	threads[ct].state = THREAD_STATE_SUSPENDED;

	threads[ct].have_user_map = core_mmu_user_mapping_is_active();
	if (threads[ct].have_user_map) {
		core_mmu_get_user_map(&threads[ct].user_map);
		core_mmu_set_user_map(NULL);
	}


	l->curr_thread = -1;

	unlock_global();

	return ct;
}


bool thread_init_stack(uint32_t thread_id, vaddr_t sp)
{
	switch (thread_id) {
	case THREAD_TMP_STACK: {
		struct thread_core_local *l = get_core_local();

		l->tmp_stack_va_end = sp;
		l->curr_thread = -1;

		thread_set_irq_sp(sp);
		thread_set_fiq_sp(sp);
		break;
	}

	case THREAD_ABT_STACK:
		thread_set_abt_sp(sp);
		break;

	default:
		if (thread_id >= NUM_THREADS)
			return false;
		if (threads[thread_id].state != THREAD_STATE_FREE)
			return false;

		threads[thread_id].stack_va_end = sp;
	}

	return true;
}

uint32_t thread_get_id(void)
{
	uint32_t cpsr = read_cpsr();
	struct thread_core_local *l;
	int ct;

	/* get_core_local() requires IRQs to be disabled */
	write_cpsr(cpsr | CPSR_I);

	l = get_core_local();
	ct = l->curr_thread;

	write_cpsr(cpsr);
	return ct;
}

void thread_init_handlers(const struct thread_handlers *handlers)
{
	/*
	 * The COMPILE_TIME_ASSERT only works in function context. These
	 * checks verifies that the offsets used in assembly code matches
	 * what's used in C code.
	 */
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r0) ==
				THREAD_SVC_REG_R0_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r1) ==
				THREAD_SVC_REG_R1_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r2) ==
				THREAD_SVC_REG_R2_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r3) ==
				THREAD_SVC_REG_R3_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r4) ==
				THREAD_SVC_REG_R4_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r5) ==
				THREAD_SVC_REG_R5_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r6) ==
				THREAD_SVC_REG_R6_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, r7) ==
				THREAD_SVC_REG_R7_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, lr) ==
				THREAD_SVC_REG_LR_OFFS);
	COMPILE_TIME_ASSERT(offsetof(struct thread_svc_regs, spsr) ==
				THREAD_SVC_REG_SPSR_OFFS);

	thread_std_smc_handler_ptr = handlers->std_smc;
	thread_fast_smc_handler_ptr = handlers->fast_smc;
	thread_fiq_handler_ptr = handlers->fiq;
	thread_svc_handler_ptr = handlers->svc;
	thread_abort_handler_ptr = handlers->abort;
	thread_cpu_on_handler_ptr = handlers->cpu_on;
	thread_cpu_off_handler_ptr = handlers->cpu_off;
	thread_cpu_suspend_handler_ptr = handlers->cpu_suspend;
	thread_cpu_resume_handler_ptr = handlers->cpu_resume;
	thread_system_off_handler_ptr = handlers->system_off;
	thread_system_reset_handler_ptr = handlers->system_reset;
}

void thread_init_per_cpu(void)
{
	thread_init_vbar();
}

void thread_set_tsd(void *tsd)
{
	uint32_t cpsr = read_cpsr();
	struct thread_core_local *l;
	int ct;

	/* get_core_local() requires IRQs to be disabled */
	write_cpsr(cpsr | CPSR_I);

	l = get_core_local();
	ct = l->curr_thread;

	assert(ct != -1);
	assert(threads[ct].state == THREAD_STATE_ACTIVE);
	threads[ct].tsd = tsd;

	write_cpsr(cpsr);
}

void *thread_get_tsd(void)
{
	uint32_t cpsr = read_cpsr();
	struct thread_core_local *l;
	int ct;
	void *tsd;

	/* get_core_local() requires IRQs to be disabled */
	write_cpsr(cpsr | CPSR_I);

	l = get_core_local();
	ct = l->curr_thread;

	if (ct == -1 || threads[ct].state != THREAD_STATE_ACTIVE)
		tsd = NULL;
	else
		tsd = threads[ct].tsd;

	write_cpsr(cpsr);
	return tsd;
}

struct thread_ctx_regs *thread_get_ctx_regs(void)
{
	struct thread_core_local *l = get_core_local();

	assert(l->curr_thread != -1);
	return &threads[l->curr_thread].regs;
}

void thread_set_irq(bool enable)
{
	struct thread_core_local *l;
	uint32_t cpsr = read_cpsr();

	/* get_core_local() requires IRQs to be disabled */
	write_cpsr(cpsr | CPSR_I);

	l = get_core_local();

	assert(l->curr_thread != -1);

	if (enable) {
		threads[l->curr_thread].flags |= THREAD_FLAGS_IRQ_ENABLE;
		write_cpsr(cpsr & ~CPSR_I);
	} else {
		/*
		 * No need to disable IRQ here since it's already disabled
		 * above.
		 */
		threads[l->curr_thread].flags &= ~THREAD_FLAGS_IRQ_ENABLE;
	}
}

void thread_restore_irq(void)
{
	struct thread_core_local *l;
	uint32_t cpsr = read_cpsr();

	/* get_core_local() requires IRQs to be disabled */
	write_cpsr(cpsr | CPSR_I);

	l = get_core_local();

	assert(l->curr_thread != -1);

	if (threads[l->curr_thread].flags & THREAD_FLAGS_IRQ_ENABLE)
		write_cpsr(cpsr & ~CPSR_I);
}

#ifdef CFG_WITH_VFP
uint32_t thread_kernel_enable_vfp(void)
{
	uint32_t cpsr = read_cpsr();

	write_cpsr(cpsr | CPSR_I);

	assert(!vfp_is_enabled());

	if (!thread_vfp_state.ns_saved) {
		vfp_lazy_save_state_final(&thread_vfp_state.ns);
		thread_vfp_state.ns_saved = true;
	} else if (thread_vfp_state.sec_lazy_saved &&
		   !thread_vfp_state.sec_saved) {
		vfp_lazy_save_state_final(&thread_vfp_state.sec);
		thread_vfp_state.sec_saved = true;
	}

	vfp_enable();
	return cpsr;
}

void thread_kernel_disable_vfp(uint32_t state)
{
	uint32_t cpsr;

	assert(vfp_is_enabled());

	vfp_disable();
	cpsr = read_cpsr();
	assert(cpsr & CPSR_I);
	cpsr &= ~CPSR_I;
	cpsr |= state & CPSR_I;
	write_cpsr(cpsr);
}
#endif /*CFG_WITH_VFP*/


paddr_t thread_rpc_alloc_arg(size_t size)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
		TEESMC_RETURN_RPC_ALLOC_ARG, size};

	thread_rpc(rpc_args);
	return rpc_args[1];
}

paddr_t thread_rpc_alloc_payload(size_t size)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
		TEESMC_RETURN_RPC_ALLOC_PAYLOAD, size};

	thread_rpc(rpc_args);
	return rpc_args[1];
}

void thread_rpc_free_arg(paddr_t arg)
{
	if (arg) {
		uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
			TEESMC_RETURN_RPC_FREE_ARG, arg};

		thread_rpc(rpc_args);
	}
}
void thread_rpc_free_payload(paddr_t payload)
{
	if (payload) {
		uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
			TEESMC_RETURN_RPC_FREE_PAYLOAD, payload};

		thread_rpc(rpc_args);
	}
}

void thread_rpc_cmd(paddr_t arg)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {TEESMC_RETURN_RPC_CMD, arg};

	thread_rpc(rpc_args);
}

void thread_optee_rpc_alloc_payload(size_t size, paddr_t *payload,
		paddr_t *cookie)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] = {
		TEESMC_RETURN_OPTEE_RPC_ALLOC_PAYLOAD, size};

	thread_rpc(rpc_args);
	if (payload)
		*payload = rpc_args[1];
	if (cookie)
		*cookie = rpc_args[2];
}

void thread_optee_rpc_free_payload(paddr_t cookie)
{
	uint32_t rpc_args[THREAD_RPC_NUM_ARGS] ={
		TEESMC_RETURN_OPTEE_RPC_FREE_PAYLOAD, cookie};

	thread_rpc(rpc_args);
}
