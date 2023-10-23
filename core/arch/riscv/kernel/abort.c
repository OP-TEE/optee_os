// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022-2023 NXP
 * Copyright (c) 2015-2022, Linaro Limited
 */

#include <kernel/abort.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread_private.h>
#include <kernel/user_mode_ctx.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <riscv.h>
#include <tee/tee_svc.h>
#include <trace.h>
#include <unw/unwind.h>

enum fault_type {
	FAULT_TYPE_USER_MODE_PANIC,
	FAULT_TYPE_USER_MODE_VFP,
	FAULT_TYPE_PAGE_FAULT,
	FAULT_TYPE_IGNORE,
};

#ifdef CFG_UNWIND

/* Kernel mode unwind */
static void __print_stack_unwind(struct abort_info *ai)
{
	struct unwind_state_riscv state = {
		.fp = ai->regs->s0,
		.pc = ai->regs->epc,
	};

	print_stack_riscv(&state, thread_stack_start(), thread_stack_size());
}

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

static __maybe_unused const char *
fault_to_str(uint32_t abort_type, uint32_t fault_descr)
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

	if (abort_is_user_exception(ai))
		core_pos = thread_get_tsd()->abort_core;
	else
		core_pos = get_core_pos();

	EMSG_RAW("");
	EMSG_RAW("%s %s-abort at address 0x%" PRIxVA "%s",
		 ctx, abort_type_to_str(ai->abort_type), ai->va,
		 fault_to_str(ai->abort_type, ai->fault_descr));
	EMSG_RAW("cpu\t#%zu", core_pos);
	EMSG_RAW("cause\t%016" PRIxPTR " epc\t%016" PRIxPTR,
		 ai->regs->cause, ai->regs->epc);
	EMSG_RAW("tval\t%016" PRIxPTR " status\t%016" PRIxPTR,
		 ai->regs->tval, ai->regs->status);
	EMSG_RAW("ra\t%016" PRIxPTR " sp\t%016" PRIxPTR,
		 ai->regs->ra, ai->regs->sp);
	EMSG_RAW("gp\t%016" PRIxPTR " tp\t%016" PRIxPTR,
		 ai->regs->gp, ai->regs->tp);
	EMSG_RAW("t0\t%016" PRIxPTR " t1\t%016" PRIxPTR,
		 ai->regs->t0, ai->regs->t1);
	EMSG_RAW("t2\t%016" PRIxPTR " s0\t%016" PRIxPTR,
		 ai->regs->t2, ai->regs->s0);
	EMSG_RAW("s1\t%016" PRIxPTR " a0\t%016" PRIxPTR,
		 ai->regs->s1, ai->regs->a0);
	EMSG_RAW("a1\t%016" PRIxPTR " a2\t%016" PRIxPTR,
		 ai->regs->a1, ai->regs->a2);
	EMSG_RAW("a3\t%016" PRIxPTR " a4\t%016" PRIxPTR,
		 ai->regs->a3, ai->regs->a4);
	EMSG_RAW("a5\t%016" PRIxPTR " a5\t%016" PRIxPTR,
		 ai->regs->a5, ai->regs->a5);
	EMSG_RAW("a6\t%016" PRIxPTR " a7\t%016" PRIxPTR,
		 ai->regs->a6, ai->regs->a7);
	EMSG_RAW("s2\t%016" PRIxPTR " s3\t%016" PRIxPTR,
		 ai->regs->s2, ai->regs->s3);
	EMSG_RAW("s4\t%016" PRIxPTR " s5\t%016" PRIxPTR,
		 ai->regs->s4, ai->regs->s5);
	EMSG_RAW("s6\t%016" PRIxPTR " s7\t%016" PRIxPTR,
		 ai->regs->s6, ai->regs->s7);
	EMSG_RAW("s8\t%016" PRIxPTR " s9\t%016" PRIxPTR,
		 ai->regs->s8, ai->regs->s9);
	EMSG_RAW("s10\t%016" PRIxPTR " s11\t%016" PRIxPTR,
		 ai->regs->s10, ai->regs->s11);
	EMSG_RAW("t3\t%016" PRIxPTR " t4\t%016" PRIxPTR,
		 ai->regs->t3, ai->regs->t4);
	EMSG_RAW("t5\t%016" PRIxPTR " t6\t%016" PRIxPTR,
		 ai->regs->t5, ai->regs->t6);
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
	ai.pc = tsd->abort_regs.epc;
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

static void set_abort_info(uint32_t abort_type __unused,
			   struct thread_abort_regs *regs,
			   struct abort_info *ai)
{
	ai->fault_descr = regs->cause;
	switch (ai->fault_descr) {
	case CAUSE_MISALIGNED_FETCH:
	case CAUSE_FETCH_ACCESS:
	case CAUSE_FETCH_PAGE_FAULT:
	case CAUSE_FETCH_GUEST_PAGE_FAULT:
		ai->abort_type = ABORT_TYPE_PREFETCH;
		break;
	case CAUSE_MISALIGNED_LOAD:
	case CAUSE_LOAD_ACCESS:
	case CAUSE_MISALIGNED_STORE:
	case CAUSE_STORE_ACCESS:
	case CAUSE_LOAD_PAGE_FAULT:
	case CAUSE_STORE_PAGE_FAULT:
	case CAUSE_LOAD_GUEST_PAGE_FAULT:
	case CAUSE_STORE_GUEST_PAGE_FAULT:
		ai->abort_type = ABORT_TYPE_DATA;
		break;
	default:
		ai->abort_type = ABORT_TYPE_UNDEF;
	}

	ai->va = regs->tval;
	ai->pc = regs->epc;
	ai->regs = regs;
}

static void handle_user_mode_panic(struct abort_info *ai)
{
	/*
	 * It was a user exception, stop user execution and return
	 * to TEE Core.
	 */
	ai->regs->a0 = TEE_ERROR_TARGET_DEAD;
	ai->regs->a1 = true;
	ai->regs->a2 = 0xdeadbeef;
	ai->regs->ra = (vaddr_t)thread_unwind_user_mode;
	ai->regs->sp = thread_get_saved_thread_sp();
	ai->regs->status = xstatus_for_xret(true, PRV_S);

	thread_exit_user_mode(ai->regs->a0, ai->regs->a1, ai->regs->a2,
			      ai->regs->a3, ai->regs->sp, ai->regs->ra,
			      ai->regs->status);
}

#ifdef CFG_WITH_VFP
static void handle_user_mode_vfp(void)
{
	struct ts_session *s = ts_get_current_session();

	thread_user_enable_vfp(&to_user_mode_ctx(s->ctx)->vfp);
}
#endif /*CFG_WITH_VFP*/

#ifdef CFG_WITH_USER_TA

/* Returns true if the exception originated from user mode */
bool abort_is_user_exception(struct abort_info *ai)
{
	return (ai->regs->status & CSR_XSTATUS_SPP) == 0;
}

#else /*CFG_WITH_USER_TA*/
bool abort_is_user_exception(struct abort_info *ai __unused)
{
	return false;
}
#endif /*CFG_WITH_USER_TA*/

#if defined(CFG_WITH_VFP) && defined(CFG_WITH_USER_TA)
static bool is_vfp_fault(struct abort_info *ai)
{
	/* Implement */
	return false;
}
#else /*CFG_WITH_VFP && CFG_WITH_USER_TA*/
static bool is_vfp_fault(struct abort_info *ai __unused)
{
	return false;
}
#endif  /*CFG_WITH_VFP && CFG_WITH_USER_TA*/

static enum fault_type get_fault_type(struct abort_info *ai)
{
	if (abort_is_user_exception(ai)) {
		if (is_vfp_fault(ai))
			return FAULT_TYPE_USER_MODE_VFP;
		return FAULT_TYPE_USER_MODE_PANIC;
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
		panic("[abort] alignment fault!  (trap CPU)");
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
		return FAULT_TYPE_PAGE_FAULT;

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

	set_abort_info(abort_type, regs, &ai);

	switch (get_fault_type(&ai)) {
	case FAULT_TYPE_IGNORE:
		break;
	case FAULT_TYPE_USER_MODE_PANIC:
		DMSG("[abort] abort in User mode (TA will panic)");
		save_abort_info_in_tsd(&ai);
#ifdef CFG_WITH_VFP
		vfp_disable();
#endif
		handle_user_mode_panic(&ai);
		break;
#ifdef CFG_WITH_VFP
	case FAULT_TYPE_USER_MODE_VFP:
		handle_user_mode_vfp();
		break;
#endif
	case FAULT_TYPE_PAGE_FAULT:
	default:
		if (thread_get_id_may_fail() < 0) {
			abort_print_error(&ai);
			panic("abort outside thread context");
		}

		if (!abort_is_user_exception(&ai)) {
			abort_print_error(&ai);
			panic("unhandled page fault abort");
		}
		DMSG("[abort] abort in User mode (TA will panic)");
		save_abort_info_in_tsd(&ai);
#ifdef CFG_WITH_VFP
		vfp_disable();
#endif
		handle_user_mode_panic(&ai);
		break;
	}
}
