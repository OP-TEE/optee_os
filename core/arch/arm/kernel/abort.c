// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2022, Linaro Limited
 */

#include <arm.h>
#include <kernel/abort.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread_private.h>
#include <kernel/user_mode_ctx.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/tee_pager.h>
#include <tee/tee_svc.h>
#include <trace.h>
#include <unw/unwind.h>

enum fault_type {
	FAULT_TYPE_USER_MODE_PANIC,
	FAULT_TYPE_USER_MODE_VFP,
	FAULT_TYPE_PAGEABLE,
	FAULT_TYPE_IGNORE,
};

#ifdef CFG_UNWIND

#ifdef ARM32
/*
 * Kernel or user mode unwind (32-bit execution state).
 */
static void __print_stack_unwind(struct abort_info *ai)
{
	struct unwind_state_arm32 state = { };
	uint32_t mode = ai->regs->spsr & CPSR_MODE_MASK;
	uint32_t sp = 0;
	uint32_t lr = 0;

	assert(!abort_is_user_exception(ai));

	if (mode == CPSR_MODE_SYS) {
		sp = ai->regs->usr_sp;
		lr = ai->regs->usr_lr;
	} else {
		sp = read_mode_sp(mode);
		lr = read_mode_lr(mode);
	}

	memset(&state, 0, sizeof(state));
	state.registers[0] = ai->regs->r0;
	state.registers[1] = ai->regs->r1;
	state.registers[2] = ai->regs->r2;
	state.registers[3] = ai->regs->r3;
	state.registers[4] = ai->regs->r4;
	state.registers[5] = ai->regs->r5;
	state.registers[6] = ai->regs->r6;
	state.registers[7] = ai->regs->r7;
	state.registers[8] = ai->regs->r8;
	state.registers[9] = ai->regs->r9;
	state.registers[10] = ai->regs->r10;
	state.registers[11] = ai->regs->r11;
	state.registers[13] = sp;
	state.registers[14] = lr;
	state.registers[15] = ai->pc;

	print_stack_arm32(&state, thread_stack_start(), thread_stack_size());
}
#endif /* ARM32 */

#ifdef ARM64
/* Kernel mode unwind (64-bit execution state) */
static void __print_stack_unwind(struct abort_info *ai)
{
	struct unwind_state_arm64 state = {
		.pc = ai->regs->elr,
		.fp = ai->regs->x29,
	};

	print_stack_arm64(&state, thread_stack_start(), thread_stack_size());
}
#endif /*ARM64*/

#else /* CFG_UNWIND */
static void __print_stack_unwind(struct abort_info *ai __unused)
{
}
#endif /* CFG_UNWIND */

static __maybe_unused const char *abort_type_to_str(uint32_t abort_type)
{
	if (abort_type == ABORT_TYPE_DATA)
		return "data";
	if (abort_type == ABORT_TYPE_PREFETCH)
		return "prefetch";
	return "undef";
}

static __maybe_unused const char *fault_to_str(uint32_t abort_type,
			uint32_t fault_descr)
{
	/* fault_descr is only valid for data or prefetch abort */
	if (abort_type != ABORT_TYPE_DATA && abort_type != ABORT_TYPE_PREFETCH)
		return "";

	switch (core_mmu_get_fault_type(fault_descr)) {
	case CORE_MMU_FAULT_ALIGNMENT:
		return " (alignment fault)";
	case CORE_MMU_FAULT_TRANSLATION:
		return " (translation fault)";
	case CORE_MMU_FAULT_READ_PERMISSION:
		return " (read permission fault)";
	case CORE_MMU_FAULT_WRITE_PERMISSION:
		return " (write permission fault)";
	case CORE_MMU_FAULT_TAG_CHECK:
		return " (tag check fault)";
	default:
		return "";
	}
}

static __maybe_unused void
__print_abort_info(struct abort_info *ai __maybe_unused,
		   const char *ctx __maybe_unused)
{
	__maybe_unused size_t core_pos = 0;
#ifdef ARM32
	uint32_t mode = ai->regs->spsr & CPSR_MODE_MASK;
	__maybe_unused uint32_t sp = 0;
	__maybe_unused uint32_t lr = 0;

	if (mode == CPSR_MODE_USR || mode == CPSR_MODE_SYS) {
		sp = ai->regs->usr_sp;
		lr = ai->regs->usr_lr;
		core_pos = thread_get_tsd()->abort_core;
	} else {
		sp = read_mode_sp(mode);
		lr = read_mode_lr(mode);
		core_pos = get_core_pos();
	}
#endif /*ARM32*/
#ifdef ARM64
	if (abort_is_user_exception(ai))
		core_pos = thread_get_tsd()->abort_core;
	else
		core_pos = get_core_pos();
#endif /*ARM64*/

	EMSG_RAW("");
	EMSG_RAW("%s %s-abort at address 0x%" PRIxVA "%s",
		ctx, abort_type_to_str(ai->abort_type), ai->va,
		fault_to_str(ai->abort_type, ai->fault_descr));
#ifdef ARM32
	EMSG_RAW(" fsr 0x%08x  ttbr0 0x%08x  ttbr1 0x%08x  cidr 0x%X",
		 ai->fault_descr, read_ttbr0(), read_ttbr1(),
		 read_contextidr());
	EMSG_RAW(" cpu #%zu          cpsr 0x%08x",
		 core_pos, ai->regs->spsr);
	EMSG_RAW(" r0 0x%08x      r4 0x%08x    r8 0x%08x   r12 0x%08x",
		 ai->regs->r0, ai->regs->r4, ai->regs->r8, ai->regs->ip);
	EMSG_RAW(" r1 0x%08x      r5 0x%08x    r9 0x%08x    sp 0x%08x",
		 ai->regs->r1, ai->regs->r5, ai->regs->r9, sp);
	EMSG_RAW(" r2 0x%08x      r6 0x%08x   r10 0x%08x    lr 0x%08x",
		 ai->regs->r2, ai->regs->r6, ai->regs->r10, lr);
	EMSG_RAW(" r3 0x%08x      r7 0x%08x   r11 0x%08x    pc 0x%08x",
		 ai->regs->r3, ai->regs->r7, ai->regs->r11, ai->pc);
#endif /*ARM32*/
#ifdef ARM64
	EMSG_RAW(" esr 0x%08x  ttbr0 0x%08" PRIx64 "   ttbr1 0x%08" PRIx64
		 "   cidr 0x%X", ai->fault_descr, read_ttbr0_el1(),
		 read_ttbr1_el1(), read_contextidr_el1());
	EMSG_RAW(" cpu #%zu          cpsr 0x%08x",
		 core_pos, (uint32_t)ai->regs->spsr);
	EMSG_RAW(" x0  %016" PRIx64 " x1  %016" PRIx64,
		 ai->regs->x0, ai->regs->x1);
	EMSG_RAW(" x2  %016" PRIx64 " x3  %016" PRIx64,
		 ai->regs->x2, ai->regs->x3);
	EMSG_RAW(" x4  %016" PRIx64 " x5  %016" PRIx64,
		 ai->regs->x4, ai->regs->x5);
	EMSG_RAW(" x6  %016" PRIx64 " x7  %016" PRIx64,
		 ai->regs->x6, ai->regs->x7);
	EMSG_RAW(" x8  %016" PRIx64 " x9  %016" PRIx64,
		 ai->regs->x8, ai->regs->x9);
	EMSG_RAW(" x10 %016" PRIx64 " x11 %016" PRIx64,
		 ai->regs->x10, ai->regs->x11);
	EMSG_RAW(" x12 %016" PRIx64 " x13 %016" PRIx64,
		 ai->regs->x12, ai->regs->x13);
	EMSG_RAW(" x14 %016" PRIx64 " x15 %016" PRIx64,
		 ai->regs->x14, ai->regs->x15);
	EMSG_RAW(" x16 %016" PRIx64 " x17 %016" PRIx64,
		 ai->regs->x16, ai->regs->x17);
	EMSG_RAW(" x18 %016" PRIx64 " x19 %016" PRIx64,
		 ai->regs->x18, ai->regs->x19);
	EMSG_RAW(" x20 %016" PRIx64 " x21 %016" PRIx64,
		 ai->regs->x20, ai->regs->x21);
	EMSG_RAW(" x22 %016" PRIx64 " x23 %016" PRIx64,
		 ai->regs->x22, ai->regs->x23);
	EMSG_RAW(" x24 %016" PRIx64 " x25 %016" PRIx64,
		 ai->regs->x24, ai->regs->x25);
	EMSG_RAW(" x26 %016" PRIx64 " x27 %016" PRIx64,
		 ai->regs->x26, ai->regs->x27);
	EMSG_RAW(" x28 %016" PRIx64 " x29 %016" PRIx64,
		 ai->regs->x28, ai->regs->x29);
	EMSG_RAW(" x30 %016" PRIx64 " elr %016" PRIx64,
		 ai->regs->x30, ai->regs->elr);
	EMSG_RAW(" sp_el0 %016" PRIx64, ai->regs->sp_el0);
#endif /*ARM64*/
}

/*
 * Print abort info and (optionally) stack dump to the console
 * @ai kernel-mode abort info.
 * @stack_dump true to show a stack trace
 */
static void __abort_print(struct abort_info *ai, bool stack_dump)
{
	assert(!abort_is_user_exception(ai));

	__print_abort_info(ai, "Core");

	if (stack_dump) {
		trace_printf_helper_raw(TRACE_ERROR, true,
					"TEE load address @ %#"PRIxVA,
					VCORE_START_VA);
		__print_stack_unwind(ai);
	}
}

void abort_print(struct abort_info *ai)
{
	__abort_print(ai, false);
}

void abort_print_error(struct abort_info *ai)
{
	__abort_print(ai, true);
}

/* This function must be called from a normal thread */
void abort_print_current_ts(void)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct abort_info ai = { };
	struct ts_session *s = ts_get_current_session();

	ai.abort_type = tsd->abort_type;
	ai.fault_descr = tsd->abort_descr;
	ai.va = tsd->abort_va;
	ai.pc = tsd->abort_regs.elr;
	ai.regs = &tsd->abort_regs;

	if (ai.abort_type != ABORT_TYPE_USER_MODE_PANIC)
		__print_abort_info(&ai, "User mode");

	s->ctx->ops->dump_state(s->ctx);

#if defined(CFG_FTRACE_SUPPORT)
	if (s->ctx->ops->dump_ftrace) {
		s->fbuf = NULL;
		s->ctx->ops->dump_ftrace(s->ctx);
	}
#endif
}

static void save_abort_info_in_tsd(struct abort_info *ai)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	tsd->abort_type = ai->abort_type;
	tsd->abort_descr = ai->fault_descr;
	tsd->abort_va = ai->va;
	tsd->abort_regs = *ai->regs;
	tsd->abort_core = get_core_pos();
}

#ifdef ARM32
static void set_abort_info(uint32_t abort_type, struct thread_abort_regs *regs,
		struct abort_info *ai)
{
	switch (abort_type) {
	case ABORT_TYPE_DATA:
		ai->fault_descr = read_dfsr();
		ai->va = read_dfar();
		break;
	case ABORT_TYPE_PREFETCH:
		ai->fault_descr = read_ifsr();
		ai->va = read_ifar();
		break;
	default:
		ai->fault_descr = 0;
		ai->va = regs->elr;
		break;
	}
	ai->abort_type = abort_type;
	ai->pc = regs->elr;
	ai->regs = regs;
}
#endif /*ARM32*/

#ifdef ARM64
static void set_abort_info(uint32_t abort_type __unused,
		struct thread_abort_regs *regs, struct abort_info *ai)
{
	ai->fault_descr = read_esr_el1();
	switch ((ai->fault_descr >> ESR_EC_SHIFT) & ESR_EC_MASK) {
	case ESR_EC_IABT_EL0:
	case ESR_EC_IABT_EL1:
		ai->abort_type = ABORT_TYPE_PREFETCH;
		ai->va = read_far_el1();
		break;
	case ESR_EC_DABT_EL0:
	case ESR_EC_DABT_EL1:
	case ESR_EC_SP_ALIGN:
		ai->abort_type = ABORT_TYPE_DATA;
		ai->va = read_far_el1();
		break;
	default:
		ai->abort_type = ABORT_TYPE_UNDEF;
		ai->va = regs->elr;
	}
	ai->pc = regs->elr;
	ai->regs = regs;
}
#endif /*ARM64*/

#ifdef ARM32
static void handle_user_mode_panic(struct abort_info *ai)
{
	/*
	 * It was a user exception, stop user execution and return
	 * to TEE Core.
	 */
	ai->regs->r0 = TEE_ERROR_TARGET_DEAD;
	ai->regs->r1 = true;
	ai->regs->r2 = 0xdeadbeef;
	ai->regs->elr = (uint32_t)thread_unwind_user_mode;
	ai->regs->spsr &= CPSR_FIA;
	ai->regs->spsr &= ~CPSR_MODE_MASK;
	ai->regs->spsr |= CPSR_MODE_SVC;
	/* Select Thumb or ARM mode */
	if (ai->regs->elr & 1)
		ai->regs->spsr |= CPSR_T;
	else
		ai->regs->spsr &= ~CPSR_T;
}
#endif /*ARM32*/

#ifdef ARM64
static void handle_user_mode_panic(struct abort_info *ai)
{
	struct thread_ctx *tc __maybe_unused = NULL;
	uint32_t daif = 0;

	/*
	 * It was a user exception, stop user execution and return
	 * to TEE Core.
	 */
	ai->regs->x0 = TEE_ERROR_TARGET_DEAD;
	ai->regs->x1 = true;
	ai->regs->x2 = 0xdeadbeef;
	ai->regs->elr = (vaddr_t)thread_unwind_user_mode;
	ai->regs->sp_el0 = thread_get_saved_thread_sp();

#if defined(CFG_CORE_PAUTH)
	/*
	 * We're going to return to the privileged core thread, update the
	 * APIA key to match the key used by the thread.
	 */
	tc = threads + thread_get_id();
	ai->regs->apiakey_hi = tc->keys.apia_hi;
	ai->regs->apiakey_lo = tc->keys.apia_lo;
#endif

	daif = (ai->regs->spsr >> SPSR_32_AIF_SHIFT) & SPSR_32_AIF_MASK;
	/* XXX what about DAIF_D? */
	ai->regs->spsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0, daif);
}
#endif /*ARM64*/

#ifdef CFG_WITH_VFP
static void handle_user_mode_vfp(void)
{
	struct ts_session *s = ts_get_current_session();

	thread_user_enable_vfp(&to_user_mode_ctx(s->ctx)->vfp);
}
#endif /*CFG_WITH_VFP*/

#ifdef CFG_WITH_USER_TA
#ifdef ARM32
/* Returns true if the exception originated from user mode */
bool abort_is_user_exception(struct abort_info *ai)
{
	return (ai->regs->spsr & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_USR;
}
#endif /*ARM32*/

#ifdef ARM64
/* Returns true if the exception originated from user mode */
bool abort_is_user_exception(struct abort_info *ai)
{
	uint32_t spsr = ai->regs->spsr;

	if (spsr & (SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT))
		return true;
	if (((spsr >> SPSR_64_MODE_EL_SHIFT) & SPSR_64_MODE_EL_MASK) ==
	    SPSR_64_MODE_EL0)
		return true;
	return false;
}
#endif /*ARM64*/
#else /*CFG_WITH_USER_TA*/
bool abort_is_user_exception(struct abort_info *ai __unused)
{
	return false;
}
#endif /*CFG_WITH_USER_TA*/

#if defined(CFG_WITH_VFP) && defined(CFG_WITH_USER_TA)
#ifdef ARM32
static bool is_vfp_fault(struct abort_info *ai)
{
	if ((ai->abort_type != ABORT_TYPE_UNDEF) || vfp_is_enabled())
		return false;

	/*
	 * Not entirely accurate, but if it's a truly undefined instruction
	 * we'll end up in this function again, except this time
	 * vfp_is_enabled() so we'll return false.
	 */
	return true;
}
#endif /*ARM32*/

#ifdef ARM64
static bool is_vfp_fault(struct abort_info *ai)
{
	switch ((ai->fault_descr >> ESR_EC_SHIFT) & ESR_EC_MASK) {
	case ESR_EC_FP_ASIMD:
	case ESR_EC_AARCH32_FP:
	case ESR_EC_AARCH64_FP:
		return true;
	default:
		return false;
	}
}
#endif /*ARM64*/
#else /*CFG_WITH_VFP && CFG_WITH_USER_TA*/
static bool is_vfp_fault(struct abort_info *ai __unused)
{
	return false;
}
#endif  /*CFG_WITH_VFP && CFG_WITH_USER_TA*/

bool abort_is_write_fault(struct abort_info *ai)
{
#ifdef ARM32
	unsigned int write_not_read = 11;
#endif
#ifdef ARM64
	unsigned int write_not_read = 6;
#endif

	return ai->abort_type == ABORT_TYPE_DATA &&
	       (ai->fault_descr & BIT(write_not_read));
}

static enum fault_type get_fault_type(struct abort_info *ai)
{
	if (abort_is_user_exception(ai)) {
		if (is_vfp_fault(ai))
			return FAULT_TYPE_USER_MODE_VFP;
#ifndef CFG_WITH_PAGER
		return FAULT_TYPE_USER_MODE_PANIC;
#endif
	}

	if (thread_is_from_abort_mode()) {
		abort_print_error(ai);
		panic("[abort] abort in abort handler (trap CPU)");
	}

	if (ai->abort_type == ABORT_TYPE_UNDEF) {
		if (abort_is_user_exception(ai))
			return FAULT_TYPE_USER_MODE_PANIC;
		abort_print_error(ai);
		panic("[abort] undefined abort (trap CPU)");
	}

	switch (core_mmu_get_fault_type(ai->fault_descr)) {
	case CORE_MMU_FAULT_ALIGNMENT:
		if (abort_is_user_exception(ai))
			return FAULT_TYPE_USER_MODE_PANIC;
		abort_print_error(ai);
		panic("[abort] alignement fault!  (trap CPU)");
		break;

	case CORE_MMU_FAULT_ACCESS_BIT:
		if (abort_is_user_exception(ai))
			return FAULT_TYPE_USER_MODE_PANIC;
		abort_print_error(ai);
		panic("[abort] access bit fault!  (trap CPU)");
		break;

	case CORE_MMU_FAULT_DEBUG_EVENT:
		if (!abort_is_user_exception(ai))
			abort_print(ai);
		DMSG("[abort] Ignoring debug event!");
		return FAULT_TYPE_IGNORE;

	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_WRITE_PERMISSION:
	case CORE_MMU_FAULT_READ_PERMISSION:
		return FAULT_TYPE_PAGEABLE;

	case CORE_MMU_FAULT_ASYNC_EXTERNAL:
		if (!abort_is_user_exception(ai))
			abort_print(ai);
		DMSG("[abort] Ignoring async external abort!");
		return FAULT_TYPE_IGNORE;

	case CORE_MMU_FAULT_TAG_CHECK:
		if (abort_is_user_exception(ai))
			return FAULT_TYPE_USER_MODE_PANIC;
		abort_print_error(ai);
		panic("[abort] Tag check fault! (trap CPU)");
		break;

	case CORE_MMU_FAULT_OTHER:
	default:
		if (!abort_is_user_exception(ai))
			abort_print(ai);
		DMSG("[abort] Unhandled fault!");
		return FAULT_TYPE_IGNORE;
	}
}

void abort_handler(uint32_t abort_type, struct thread_abort_regs *regs)
{
	struct abort_info ai;
	bool handled;

	set_abort_info(abort_type, regs, &ai);

	switch (get_fault_type(&ai)) {
	case FAULT_TYPE_IGNORE:
		break;
	case FAULT_TYPE_USER_MODE_PANIC:
		DMSG("[abort] abort in User mode (TA will panic)");
		save_abort_info_in_tsd(&ai);
		vfp_disable();
		handle_user_mode_panic(&ai);
		break;
#ifdef CFG_WITH_VFP
	case FAULT_TYPE_USER_MODE_VFP:
		handle_user_mode_vfp();
		break;
#endif
	case FAULT_TYPE_PAGEABLE:
	default:
		if (thread_get_id_may_fail() < 0) {
			abort_print_error(&ai);
			panic("abort outside thread context");
		}
		thread_kernel_save_vfp();
		handled = tee_pager_handle_fault(&ai);
		thread_kernel_restore_vfp();
		if (!handled) {
			if (!abort_is_user_exception(&ai)) {
				abort_print_error(&ai);
				panic("unhandled pageable abort");
			}
			DMSG("[abort] abort in User mode (TA will panic)");
			save_abort_info_in_tsd(&ai);
			vfp_disable();
			handle_user_mode_panic(&ai);
		}
		break;
	}
}
