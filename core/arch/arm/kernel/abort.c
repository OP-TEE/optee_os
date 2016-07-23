/*
 * Copyright (c) 2015, Linaro Limited
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

#include <kernel/abort.h>
#include <kernel/misc.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/panic.h>
#include <kernel/user_ta.h>
#include <kernel/unwind.h>
#include <mm/core_mmu.h>
#include <mm/tee_pager.h>
#include <tee/tee_svc.h>
#include <trace.h>
#include <arm.h>

enum fault_type {
	FAULT_TYPE_USER_TA_PANIC,
	FAULT_TYPE_USER_TA_VFP,
	FAULT_TYPE_PAGEABLE,
	FAULT_TYPE_IGNORE,
};

#ifdef CFG_CORE_UNWIND
#ifdef ARM32
static void __print_stack_unwind(struct abort_info *ai)
{
	struct unwind_state state;

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
	state.registers[13] = read_mode_sp(ai->regs->spsr & CPSR_MODE_MASK);
	state.registers[14] = read_mode_lr(ai->regs->spsr & CPSR_MODE_MASK);
	state.registers[15] = ai->pc;

	do {
		EMSG_RAW(" pc 0x%08x", state.registers[15]);
	} while (unwind_stack(&state));
}
#endif /*ARM32*/

#ifdef ARM64
static void __print_stack_unwind(struct abort_info *ai)
{
	struct unwind_state state;

	memset(&state, 0, sizeof(state));
	state.pc = ai->regs->elr;
	state.fp = ai->regs->x29;

	do {
		EMSG_RAW("pc  0x%016" PRIx64, state.pc);
	} while (unwind_stack(&state));
}
#endif /*ARM64*/

static void print_stack_unwind(struct abort_info *ai)
{
	EMSG_RAW("Call stack:");
	__print_stack_unwind(ai);
}
#else /*CFG_CORE_UNWIND*/
static void print_stack_unwind(struct abort_info *ai __unused)
{
}
#endif /*CFG_CORE_UNWIND*/

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

static __maybe_unused void print_detailed_abort(
				struct abort_info *ai __maybe_unused,
				const char *ctx __maybe_unused)
{
	EMSG_RAW("\n");
	EMSG_RAW("%s %s-abort at address 0x%" PRIxVA "%s\n",
		ctx, abort_type_to_str(ai->abort_type), ai->va,
		fault_to_str(ai->abort_type, ai->fault_descr));
#ifdef ARM32
	EMSG_RAW(" fsr 0x%08x  ttbr0 0x%08x  ttbr1 0x%08x  cidr 0x%X\n",
		 ai->fault_descr, read_ttbr0(), read_ttbr1(),
		 read_contextidr());
	EMSG_RAW(" cpu #%zu          cpsr 0x%08x\n",
		 get_core_pos(), ai->regs->spsr);
	EMSG_RAW(" r0 0x%08x      r4 0x%08x    r8 0x%08x   r12 0x%08x\n",
		 ai->regs->r0, ai->regs->r4, ai->regs->r8, ai->regs->ip);
	EMSG_RAW(" r1 0x%08x      r5 0x%08x    r9 0x%08x    sp 0x%08x\n",
		 ai->regs->r1, ai->regs->r5, ai->regs->r9,
		 read_mode_sp(ai->regs->spsr & CPSR_MODE_MASK));
	EMSG_RAW(" r2 0x%08x      r6 0x%08x   r10 0x%08x    lr 0x%08x\n",
		 ai->regs->r2, ai->regs->r6, ai->regs->r10,
		 read_mode_lr(ai->regs->spsr & CPSR_MODE_MASK));
	EMSG_RAW(" r3 0x%08x      r7 0x%08x   r11 0x%08x    pc 0x%08x\n",
		 ai->regs->r3, ai->regs->r7, ai->regs->r11, ai->pc);
#endif /*ARM32*/
#ifdef ARM64
	EMSG_RAW(" esr 0x%08x  ttbr0 0x%08" PRIx64 "   ttbr1 0x%08" PRIx64 "   cidr 0x%X\n",
		 ai->fault_descr, read_ttbr0_el1(), read_ttbr1_el1(),
		 read_contextidr_el1());
	EMSG_RAW(" cpu #%zu          cpsr 0x%08x\n",
		 get_core_pos(), (uint32_t)ai->regs->spsr);
	EMSG_RAW("x0  %016" PRIx64 " x1  %016" PRIx64,
		 ai->regs->x0, ai->regs->x1);
	EMSG_RAW("x2  %016" PRIx64 " x3  %016" PRIx64,
		 ai->regs->x2, ai->regs->x3);
	EMSG_RAW("x4  %016" PRIx64 " x5  %016" PRIx64,
		 ai->regs->x4, ai->regs->x5);
	EMSG_RAW("x6  %016" PRIx64 " x7  %016" PRIx64,
		 ai->regs->x6, ai->regs->x7);
	EMSG_RAW("x8  %016" PRIx64 " x9  %016" PRIx64,
		 ai->regs->x8, ai->regs->x9);
	EMSG_RAW("x10 %016" PRIx64 " x11 %016" PRIx64,
		 ai->regs->x10, ai->regs->x11);
	EMSG_RAW("x12 %016" PRIx64 " x13 %016" PRIx64,
		 ai->regs->x12, ai->regs->x13);
	EMSG_RAW("x14 %016" PRIx64 " x15 %016" PRIx64,
		 ai->regs->x14, ai->regs->x15);
	EMSG_RAW("x16 %016" PRIx64 " x17 %016" PRIx64,
		 ai->regs->x16, ai->regs->x17);
	EMSG_RAW("x18 %016" PRIx64 " x19 %016" PRIx64,
		 ai->regs->x18, ai->regs->x19);
	EMSG_RAW("x20 %016" PRIx64 " x21 %016" PRIx64,
		 ai->regs->x20, ai->regs->x21);
	EMSG_RAW("x22 %016" PRIx64 " x23 %016" PRIx64,
		 ai->regs->x22, ai->regs->x23);
	EMSG_RAW("x24 %016" PRIx64 " x25 %016" PRIx64,
		 ai->regs->x24, ai->regs->x25);
	EMSG_RAW("x26 %016" PRIx64 " x27 %016" PRIx64,
		 ai->regs->x26, ai->regs->x27);
	EMSG_RAW("x28 %016" PRIx64 " x29 %016" PRIx64,
		 ai->regs->x28, ai->regs->x29);
	EMSG_RAW("x30 %016" PRIx64 " elr %016" PRIx64,
		 ai->regs->x30, ai->regs->elr);
	EMSG_RAW("sp_el0 %016" PRIx64, ai->regs->sp_el0);
#endif /*ARM64*/
}

static void print_user_abort(struct abort_info *ai __maybe_unused)
{
#ifdef CFG_TEE_CORE_TA_TRACE
	print_detailed_abort(ai, "user TA");
	tee_ta_dump_current();
#endif
}

void abort_print(struct abort_info *ai __maybe_unused)
{
#if (TRACE_LEVEL >= TRACE_INFO)
	print_detailed_abort(ai, "core");
#endif /*TRACE_LEVEL >= TRACE_DEBUG*/
}

void abort_print_error(struct abort_info *ai)
{
#if (TRACE_LEVEL >= TRACE_INFO)
	/* full verbose log at DEBUG level */
	print_detailed_abort(ai, "core");
#else
#ifdef ARM32
	EMSG("%s-abort at 0x%" PRIxVA "\n"
	     "FSR 0x%x PC 0x%x TTBR0 0x%X CONTEXIDR 0x%X\n"
	     "CPUID 0x%x CPSR 0x%x (read from SPSR)",
	     abort_type_to_str(ai->abort_type),
	     ai->va, ai->fault_descr, ai->pc, read_ttbr0(), read_contextidr(),
	     read_mpidr(), read_spsr());
#endif /*ARM32*/
#ifdef ARM64
	EMSG("%s-abort at 0x%" PRIxVA "\n"
	     "ESR 0x%x PC 0x%x TTBR0 0x%" PRIx64 " CONTEXIDR 0x%X\n"
	     "CPUID 0x%" PRIx64 " CPSR 0x%x (read from SPSR)",
	     abort_type_to_str(ai->abort_type),
	     ai->va, ai->fault_descr, ai->pc, read_ttbr0_el1(),
	     read_contextidr_el1(),
	     read_mpidr_el1(), (uint32_t)ai->regs->spsr);
#endif /*ARM64*/
#endif /*TRACE_LEVEL >= TRACE_DEBUG*/
	print_stack_unwind(ai);
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
	ai->regs->spsr = read_cpsr();
	ai->regs->spsr &= ~CPSR_MODE_MASK;
	ai->regs->spsr |= CPSR_MODE_SVC;
	ai->regs->spsr &= ~CPSR_FIA;
	ai->regs->spsr |= read_spsr() & CPSR_FIA;
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

#ifdef ARM32
/* Returns true if the exception originated from abort mode */
static bool is_abort_in_abort_handler(struct abort_info *ai)
{
	return (ai->regs->spsr & ARM32_CPSR_MODE_MASK) == ARM32_CPSR_MODE_ABT;
}
#endif /*ARM32*/

#ifdef ARM64
/* Returns true if the exception originated from abort mode */
static bool is_abort_in_abort_handler(struct abort_info *ai __unused)
{
	return false;
}
#endif /*ARM64*/


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

	if (is_abort_in_abort_handler(ai)) {
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
		print_user_abort(&ai);
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
			if (!abort_is_user_exception(&ai)) {
				abort_print_error(&ai);
				panic("unhandled pageable abort");
			}
			print_user_abort(&ai);
			DMSG("[abort] abort in User mode (TA will panic)");
			vfp_disable();
			handle_user_ta_panic(&ai);
		}
		break;
	}
}
