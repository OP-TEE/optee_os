// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <arm.h>
#include <kernel/abort.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/unwind.h>
#include <kernel/user_ta.h>
#include <mm/core_mmu.h>
#include <mm/mobj.h>
#include <mm/tee_pager.h>
#include <tee/tee_svc.h>
#include <trace.h>

#include "thread_private.h"

enum fault_type {
	FAULT_TYPE_USER_TA_PANIC,
	FAULT_TYPE_USER_TA_VFP,
	FAULT_TYPE_PAGEABLE,
	FAULT_TYPE_IGNORE,
};

#ifdef CFG_UNWIND

static void get_current_ta_exidx(uaddr_t *exidx, size_t *exidx_sz)
{
	struct tee_ta_session *s;
	struct user_ta_ctx *utc;

	if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
		panic();

	utc = to_user_ta_ctx(s->ctx);

	/* Only 32-bit TAs use .ARM.exidx/.ARM.extab exception handling */
	assert(utc->is_32bit);

	*exidx = utc->exidx_start; /* NULL if TA has no unwind tables */
	if (*exidx)
		*exidx += utc->load_addr;
	*exidx_sz = utc->exidx_size;
}

#ifdef ARM32

/*
 * Kernel or user mode unwind (32-bit execution state).
 */
static void __print_stack_unwind_arm32(struct abort_info *ai)
{
	struct unwind_state_arm32 state;
	uaddr_t exidx;
	size_t exidx_sz;
	uint32_t mode = ai->regs->spsr & CPSR_MODE_MASK;
	uint32_t sp;
	uint32_t lr;

	if (abort_is_user_exception(ai)) {
		get_current_ta_exidx(&exidx, &exidx_sz);
		if (!exidx) {
			EMSG_RAW("Call stack not available");
			return;
		}
	} else {
		exidx = (vaddr_t)__exidx_start;
		exidx_sz = (vaddr_t)__exidx_end - (vaddr_t)__exidx_start;
	}

	if (mode == CPSR_MODE_USR || mode == CPSR_MODE_SYS) {
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

	print_stack_arm32(TRACE_ERROR, &state, exidx, exidx_sz);
}
#else /* ARM32 */

static void __print_stack_unwind_arm32(struct abort_info *ai __unused)
{
	struct unwind_state_arm32 state;
	uaddr_t exidx;
	size_t exidx_sz;

	/* 64-bit kernel, hence 32-bit unwind must be for user mode */
	assert(abort_is_user_exception(ai));

	get_current_ta_exidx(&exidx, &exidx_sz);

	memset(&state, 0, sizeof(state));
	state.registers[0] = ai->regs->x0;
	state.registers[1] = ai->regs->x1;
	state.registers[2] = ai->regs->x2;
	state.registers[3] = ai->regs->x3;
	state.registers[4] = ai->regs->x4;
	state.registers[5] = ai->regs->x5;
	state.registers[6] = ai->regs->x6;
	state.registers[7] = ai->regs->x7;
	state.registers[8] = ai->regs->x8;
	state.registers[9] = ai->regs->x9;
	state.registers[10] = ai->regs->x10;
	state.registers[11] = ai->regs->x11;

	state.registers[13] = ai->regs->x13;
	state.registers[14] = ai->regs->x14;
	state.registers[15] = ai->pc;

	print_stack_arm32(TRACE_ERROR, &state, exidx, exidx_sz);
}
#endif /* ARM32 */
#ifdef ARM64
/* Kernel or user mode unwind (64-bit execution state) */
static void __print_stack_unwind_arm64(struct abort_info *ai)
{
	struct unwind_state_arm64 state;
	uaddr_t stack;
	size_t stack_size;

	if (abort_is_user_exception(ai)) {
		struct tee_ta_session *s;
		struct user_ta_ctx *utc;

		if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
			panic();

		utc = to_user_ta_ctx(s->ctx);
		/* User stack */
		stack = (uaddr_t)utc->mmu->regions[0].va;
		stack_size = utc->mobj_stack->size;
	} else {
		/* Kernel stack */
		stack = thread_stack_start();
		stack_size = thread_stack_size();
	}

	memset(&state, 0, sizeof(state));
	state.pc = ai->regs->elr;
	state.fp = ai->regs->x29;

	print_stack_arm64(TRACE_ERROR, &state, stack, stack_size);
}
#else
static void __print_stack_unwind_arm64(struct abort_info *ai __unused)
{

}
#endif /*ARM64*/
#else /* CFG_UNWIND */
static void __print_stack_unwind_arm32(struct abort_info *ai __unused)
{
}

static void __print_stack_unwind_arm64(struct abort_info *ai __unused)
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
	default:
		return "";
	}
}

static __maybe_unused void
__print_abort_info(struct abort_info *ai __maybe_unused,
		   const char *ctx __maybe_unused)
{
#ifdef ARM32
	uint32_t mode = ai->regs->spsr & CPSR_MODE_MASK;
	__maybe_unused uint32_t sp;
	__maybe_unused uint32_t lr;

	if (mode == CPSR_MODE_USR || mode == CPSR_MODE_SYS) {
		sp = ai->regs->usr_sp;
		lr = ai->regs->usr_lr;
	} else {
		sp = read_mode_sp(mode);
		lr = read_mode_lr(mode);
	}
#endif /*ARM32*/

	EMSG_RAW("");
	EMSG_RAW("%s %s-abort at address 0x%" PRIxVA "%s",
		ctx, abort_type_to_str(ai->abort_type), ai->va,
		fault_to_str(ai->abort_type, ai->fault_descr));
#ifdef ARM32
	EMSG_RAW(" fsr 0x%08x  ttbr0 0x%08x  ttbr1 0x%08x  cidr 0x%X",
		 ai->fault_descr, read_ttbr0(), read_ttbr1(),
		 read_contextidr());
	EMSG_RAW(" cpu #%zu          cpsr 0x%08x",
		 get_core_pos(), ai->regs->spsr);
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
		 get_core_pos(), (uint32_t)ai->regs->spsr);
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

#if defined(ARM32)
static const bool kernel_is32bit = true;
#elif defined(ARM64)
static const bool kernel_is32bit;
#endif

/*
 * Print abort info and (optionally) stack dump to the console
 * @ai user-mode or kernel-mode abort info. If user mode, the current session
 * must be the one of the TA that caused the abort.
 * @stack_dump true to show a stack trace
 */
static void __abort_print(struct abort_info *ai, bool stack_dump)
{
	bool is_32bit;
	bool paged_ta_abort = false;

	if (abort_is_user_exception(ai)) {
		struct tee_ta_session *s;
		struct user_ta_ctx *utc;

		if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
			panic();

		utc = to_user_ta_ctx(s->ctx);
		is_32bit = utc->is_32bit;
#ifdef CFG_PAGED_USER_TA
		/*
		 * It is not safe to unwind paged TAs that received an abort,
		 * because we currently don't handle page faults that could
		 * occur when accessing the TA memory (unwind tables for
		 * instance).
		 */
		if (ai->abort_type != ABORT_TYPE_TA_PANIC)
			paged_ta_abort = true;
#endif
		if (ai->abort_type != ABORT_TYPE_TA_PANIC)
			__print_abort_info(ai, "User TA");
		tee_ta_dump_current();
	} else {
		is_32bit = kernel_is32bit;

		__print_abort_info(ai, "Core");
	}

	if (!stack_dump || paged_ta_abort)
		return;

	if (is_32bit)
		__print_stack_unwind_arm32(ai);
	else
		__print_stack_unwind_arm64(ai);
}

void abort_print(struct abort_info *ai)
{
	__abort_print(ai, false);
}

void abort_print_error(struct abort_info *ai)
{
	__abort_print(ai, true);
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
static void handle_user_ta_panic(struct abort_info *ai)
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
static void handle_user_ta_panic(struct abort_info *ai)
{
	uint32_t daif;

	/*
	 * It was a user exception, stop user execution and return
	 * to TEE Core.
	 */
	ai->regs->x0 = TEE_ERROR_TARGET_DEAD;
	ai->regs->x1 = true;
	ai->regs->x2 = 0xdeadbeef;
	ai->regs->elr = (vaddr_t)thread_unwind_user_mode;
	ai->regs->sp_el0 = thread_get_saved_thread_sp();

	daif = (ai->regs->spsr >> SPSR_32_AIF_SHIFT) & SPSR_32_AIF_MASK;
	/* XXX what about DAIF_D? */
	ai->regs->spsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0, daif);
}
#endif /*ARM64*/

#ifdef CFG_WITH_VFP
static void handle_user_ta_vfp(void)
{
	struct tee_ta_session *s;

	if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
		panic();

	thread_user_enable_vfp(&to_user_ta_ctx(s->ctx)->vfp);
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

#define T32_INSTR(w1, w0) \
	((((uint32_t)(w0) & 0xffff) << 16) | ((uint32_t)(w1) & 0xffff))

#define T32_VTRANS32_MASK	T32_INSTR(0xff << 8, (7 << 9) | 1 << 4)
#define T32_VTRANS32_VAL	T32_INSTR(0xee << 8, (5 << 9) | 1 << 4)

#define T32_VTRANS64_MASK	T32_INSTR((0xff << 8) | (7 << 5), 7 << 9)
#define T32_VTRANS64_VAL	T32_INSTR((0xec << 8) | (2 << 5), 5 << 9)

#define T32_VLDST_MASK		T32_INSTR((0xff << 8) | (1 << 4), 0)
#define T32_VLDST_VAL		T32_INSTR( 0xf9 << 8            , 0)

#define T32_VXLDST_MASK		T32_INSTR(0xfc << 8, 7 << 9)
#define T32_VXLDST_VAL		T32_INSTR(0xec << 8, 5 << 9)

#define T32_VPROC_MASK		T32_INSTR(0xef << 8, 0)
#define T32_VPROC_VAL		T32_VPROC_MASK

#define A32_INSTR(x)		((uint32_t)(x))

#define A32_VTRANS32_MASK	A32_INSTR(SHIFT_U32(0xf, 24) | \
					  SHIFT_U32(7, 9) | BIT32(4))
#define A32_VTRANS32_VAL	A32_INSTR(SHIFT_U32(0xe, 24) | \
					  SHIFT_U32(5, 9) | BIT32(4))

#define A32_VTRANS64_MASK	A32_INSTR(SHIFT_U32(0x7f, 21) | SHIFT_U32(7, 9))
#define A32_VTRANS64_VAL	A32_INSTR(SHIFT_U32(0x62, 21) | SHIFT_U32(5, 9))

#define A32_VLDST_MASK		A32_INSTR(SHIFT_U32(0xff, 24) | BIT32(20))
#define A32_VLDST_VAL		A32_INSTR(SHIFT_U32(0xf4, 24))
#define A32_VXLDST_MASK		A32_INSTR(SHIFT_U32(7, 25) | SHIFT_U32(7, 9))
#define A32_VXLDST_VAL		A32_INSTR(SHIFT_U32(6, 25) | SHIFT_U32(5, 9))

#define A32_VPROC_MASK		A32_INSTR(SHIFT_U32(0x7f, 25))
#define A32_VPROC_VAL		A32_INSTR(SHIFT_U32(0x79, 25))

static bool is_vfp_fault(struct abort_info *ai)
{
	TEE_Result res;
	uint32_t instr;

	if ((ai->abort_type != ABORT_TYPE_UNDEF) || vfp_is_enabled())
		return false;

	res = tee_svc_copy_from_user(&instr, (void *)ai->pc, sizeof(instr));
	if (res != TEE_SUCCESS)
		return false;

	if (ai->regs->spsr & CPSR_T) {
		/* Thumb mode */
		return ((instr & T32_VTRANS32_MASK) == T32_VTRANS32_VAL) ||
		       ((instr & T32_VTRANS64_MASK) == T32_VTRANS64_VAL) ||
		       ((instr & T32_VLDST_MASK) == T32_VLDST_VAL) ||
		       ((instr & T32_VXLDST_MASK) == T32_VXLDST_VAL) ||
		       ((instr & T32_VPROC_MASK) == T32_VPROC_VAL);
	} else {
		/* ARM mode */
		return ((instr & A32_VTRANS32_MASK) == A32_VTRANS32_VAL) ||
		       ((instr & A32_VTRANS64_MASK) == A32_VTRANS64_VAL) ||
		       ((instr & A32_VLDST_MASK) == A32_VLDST_VAL) ||
		       ((instr & A32_VXLDST_MASK) == A32_VXLDST_VAL) ||
		       ((instr & A32_VPROC_MASK) == A32_VPROC_VAL);
	}
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

static enum fault_type get_fault_type(struct abort_info *ai)
{
	if (abort_is_user_exception(ai)) {
		if (is_vfp_fault(ai))
			return FAULT_TYPE_USER_TA_VFP;
#ifndef CFG_WITH_PAGER
		return FAULT_TYPE_USER_TA_PANIC;
#endif
	}

	if (thread_is_from_abort_mode()) {
		abort_print_error(ai);
		panic("[abort] abort in abort handler (trap CPU)");
	}

	if (ai->abort_type == ABORT_TYPE_UNDEF) {
		if (abort_is_user_exception(ai))
			return FAULT_TYPE_USER_TA_PANIC;
		abort_print_error(ai);
		panic("[abort] undefined abort (trap CPU)");
	}

	switch (core_mmu_get_fault_type(ai->fault_descr)) {
	case CORE_MMU_FAULT_ALIGNMENT:
		if (abort_is_user_exception(ai))
			return FAULT_TYPE_USER_TA_PANIC;
		abort_print_error(ai);
		panic("[abort] alignement fault!  (trap CPU)");
		break;

	case CORE_MMU_FAULT_ACCESS_BIT:
		if (abort_is_user_exception(ai))
			return FAULT_TYPE_USER_TA_PANIC;
		abort_print_error(ai);
		panic("[abort] access bit fault!  (trap CPU)");
		break;

	case CORE_MMU_FAULT_DEBUG_EVENT:
		abort_print(ai);
		DMSG("[abort] Ignoring debug event!");
		return FAULT_TYPE_IGNORE;

	case CORE_MMU_FAULT_TRANSLATION:
	case CORE_MMU_FAULT_WRITE_PERMISSION:
	case CORE_MMU_FAULT_READ_PERMISSION:
		return FAULT_TYPE_PAGEABLE;

	case CORE_MMU_FAULT_ASYNC_EXTERNAL:
		abort_print(ai);
		DMSG("[abort] Ignoring async external abort!");
		return FAULT_TYPE_IGNORE;

	case CORE_MMU_FAULT_OTHER:
	default:
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
	case FAULT_TYPE_USER_TA_PANIC:
		DMSG("[abort] abort in User mode (TA will panic)");
		abort_print_error(&ai);
		vfp_disable();
		handle_user_ta_panic(&ai);
		break;
#ifdef CFG_WITH_VFP
	case FAULT_TYPE_USER_TA_VFP:
		handle_user_ta_vfp();
		break;
#endif
	case FAULT_TYPE_PAGEABLE:
	default:
		thread_kernel_save_vfp();
		handled = tee_pager_handle_fault(&ai);
		thread_kernel_restore_vfp();
		if (!handled) {
			abort_print_error(&ai);
			if (!abort_is_user_exception(&ai))
				panic("unhandled pageable abort");
			DMSG("[abort] abort in User mode (TA will panic)");
			vfp_disable();
			handle_user_ta_panic(&ai);
		}
		break;
	}
}
