// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <arm.h>
#include <assert.h>
#include <kernel/abort.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/trace_ta.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu.h>
#include <string.h>
#include <tee/tee_svc.h>
#include <tee/arch_svc.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc_storage.h>
#include <tee/svc_cache.h>
#include <tee_syscall_numbers.h>
#include <trace.h>
#include <util.h>

#include "arch_svc_private.h"

#if (TRACE_LEVEL == TRACE_FLOW) && defined(CFG_TEE_CORE_TA_TRACE)
#define TRACE_SYSCALLS
#endif

struct syscall_entry {
	syscall_t fn;
#ifdef TRACE_SYSCALLS
	const char *name;
#endif
};

#ifdef TRACE_SYSCALLS
#define SYSCALL_ENTRY(_fn) { .fn = (syscall_t)_fn, .name = #_fn }
#else
#define SYSCALL_ENTRY(_fn) { .fn = (syscall_t)_fn }
#endif

/*
 * This array is ordered according to the SYSCALL ids TEE_SCN_xxx
 */
static const struct syscall_entry tee_svc_syscall_table[] = {
	SYSCALL_ENTRY(syscall_sys_return),
	SYSCALL_ENTRY(syscall_log),
	SYSCALL_ENTRY(syscall_panic),
	SYSCALL_ENTRY(syscall_get_property),
	SYSCALL_ENTRY(syscall_get_property_name_to_index),
	SYSCALL_ENTRY(syscall_open_ta_session),
	SYSCALL_ENTRY(syscall_close_ta_session),
	SYSCALL_ENTRY(syscall_invoke_ta_command),
	SYSCALL_ENTRY(syscall_check_access_rights),
	SYSCALL_ENTRY(syscall_get_cancellation_flag),
	SYSCALL_ENTRY(syscall_unmask_cancellation),
	SYSCALL_ENTRY(syscall_mask_cancellation),
	SYSCALL_ENTRY(syscall_wait),
	SYSCALL_ENTRY(syscall_get_time),
	SYSCALL_ENTRY(syscall_set_ta_time),
	SYSCALL_ENTRY(syscall_cryp_state_alloc),
	SYSCALL_ENTRY(syscall_cryp_state_copy),
	SYSCALL_ENTRY(syscall_cryp_state_free),
	SYSCALL_ENTRY(syscall_hash_init),
	SYSCALL_ENTRY(syscall_hash_update),
	SYSCALL_ENTRY(syscall_hash_final),
	SYSCALL_ENTRY(syscall_cipher_init),
	SYSCALL_ENTRY(syscall_cipher_update),
	SYSCALL_ENTRY(syscall_cipher_final),
	SYSCALL_ENTRY(syscall_cryp_obj_get_info),
	SYSCALL_ENTRY(syscall_cryp_obj_restrict_usage),
	SYSCALL_ENTRY(syscall_cryp_obj_get_attr),
	SYSCALL_ENTRY(syscall_cryp_obj_alloc),
	SYSCALL_ENTRY(syscall_cryp_obj_close),
	SYSCALL_ENTRY(syscall_cryp_obj_reset),
	SYSCALL_ENTRY(syscall_cryp_obj_populate),
	SYSCALL_ENTRY(syscall_cryp_obj_copy),
	SYSCALL_ENTRY(syscall_cryp_derive_key),
	SYSCALL_ENTRY(syscall_cryp_random_number_generate),
	SYSCALL_ENTRY(syscall_authenc_init),
	SYSCALL_ENTRY(syscall_authenc_update_aad),
	SYSCALL_ENTRY(syscall_authenc_update_payload),
	SYSCALL_ENTRY(syscall_authenc_enc_final),
	SYSCALL_ENTRY(syscall_authenc_dec_final),
	SYSCALL_ENTRY(syscall_asymm_operate),
	SYSCALL_ENTRY(syscall_asymm_verify),
	SYSCALL_ENTRY(syscall_storage_obj_open),
	SYSCALL_ENTRY(syscall_storage_obj_create),
	SYSCALL_ENTRY(syscall_storage_obj_del),
	SYSCALL_ENTRY(syscall_storage_obj_rename),
	SYSCALL_ENTRY(syscall_storage_alloc_enum),
	SYSCALL_ENTRY(syscall_storage_free_enum),
	SYSCALL_ENTRY(syscall_storage_reset_enum),
	SYSCALL_ENTRY(syscall_storage_start_enum),
	SYSCALL_ENTRY(syscall_storage_next_enum),
	SYSCALL_ENTRY(syscall_storage_obj_read),
	SYSCALL_ENTRY(syscall_storage_obj_write),
	SYSCALL_ENTRY(syscall_storage_obj_trunc),
	SYSCALL_ENTRY(syscall_storage_obj_seek),
	SYSCALL_ENTRY(syscall_obj_generate_key),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_not_supported),
	SYSCALL_ENTRY(syscall_cache_operation),
};

#ifdef TRACE_SYSCALLS
static void trace_syscall(size_t num)
{
	if (num == TEE_SCN_RETURN || num > TEE_SCN_MAX)
		return;
	FMSG("syscall #%zu (%s)", num, tee_svc_syscall_table[num].name);
}
#else
static void trace_syscall(size_t num __unused)
{
}
#endif

#ifdef CFG_SYSCALL_FTRACE
static void __noprof ftrace_syscall_enter(size_t num)
{
	struct tee_ta_session *s = NULL;

	/*
	 * Syscalls related to inter-TA communication can't be traced in the
	 * caller TA's ftrace buffer as it involves context switching to callee
	 * TA's context. Moreover, user can enable ftrace for callee TA to dump
	 * function trace in corresponding ftrace buffer.
	 */
	if (num == TEE_SCN_OPEN_TA_SESSION || num == TEE_SCN_CLOSE_TA_SESSION ||
	    num == TEE_SCN_INVOKE_TA_COMMAND)
		return;

	s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);
	if (!s)
		return;

	if (s->fbuf)
		s->fbuf->syscall_trace_enabled = true;
}

static void __noprof ftrace_syscall_leave(void)
{
	struct tee_ta_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (!s)
		return;

	if (s->fbuf)
		s->fbuf->syscall_trace_enabled = false;
}
#else
static void __noprof ftrace_syscall_enter(size_t num __unused)
{
}

static void __noprof ftrace_syscall_leave(void)
{
}
#endif

#ifdef ARM32
static void get_scn_max_args(struct thread_svc_regs *regs, size_t *scn,
		size_t *max_args)
{
	*scn = regs->r7;
	*max_args = regs->r6;
}
#endif /*ARM32*/

#ifdef ARM64
static void get_scn_max_args(struct thread_svc_regs *regs, size_t *scn,
		size_t *max_args)
{
	if (((regs->spsr >> SPSR_MODE_RW_SHIFT) & SPSR_MODE_RW_MASK) ==
	     SPSR_MODE_RW_32) {
		*scn = regs->x7;
		*max_args = regs->x6;
	} else {
		*scn = regs->x8;
		*max_args = 0;
	}
}
#endif /*ARM64*/

#ifdef ARM32
static void set_svc_retval(struct thread_svc_regs *regs, uint32_t ret_val)
{
	regs->r0 = ret_val;
}
#endif /*ARM32*/

#ifdef ARM64
static void set_svc_retval(struct thread_svc_regs *regs, uint64_t ret_val)
{
	regs->x0 = ret_val;
}
#endif /*ARM64*/

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak tee_svc_handler(struct thread_svc_regs *regs)
{
	size_t scn;
	size_t max_args;
	syscall_t scf;
	uint32_t state;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(tee_svc_syscall_table) ==
				(TEE_SCN_MAX + 1));

	/* Enable native interupts */
	state = thread_get_exceptions();
	thread_unmask_exceptions(state & ~THREAD_EXCP_NATIVE_INTR);

	thread_user_save_vfp();

	/* TA has just entered kernel mode */
	tee_ta_update_session_utime_suspend();

	/* Restore foreign interrupts which are disabled on exception entry */
	thread_restore_foreign_intr();

	get_scn_max_args(regs, &scn, &max_args);

	trace_syscall(scn);

	if (max_args > TEE_SVC_MAX_ARGS) {
		DMSG("Too many arguments for SCN %zu (%zu)", scn, max_args);
		set_svc_retval(regs, TEE_ERROR_GENERIC);
		return;
	}

	if (scn > TEE_SCN_MAX)
		scf = (syscall_t)syscall_not_supported;
	else
		scf = tee_svc_syscall_table[scn].fn;

	ftrace_syscall_enter(scn);

	set_svc_retval(regs, tee_svc_do_call(regs, scf));

	ftrace_syscall_leave();

	if (scn != TEE_SCN_RETURN) {
		/* We're about to switch back to user mode */
		tee_ta_update_session_utime_resume();
	}
}

#define TA32_CONTEXT_MAX_SIZE		(14 * sizeof(uint32_t))
#define TA64_CONTEXT_MAX_SIZE		(2 * sizeof(uint64_t))

#ifdef ARM32
#ifdef CFG_UNWIND
/* Get register values pushed onto the stack by utee_panic() */
static void save_panic_regs_a32_ta(struct thread_specific_data *tsd,
				  uint32_t *pushed)
{
	tsd->abort_regs = (struct thread_abort_regs){
		.elr = pushed[0],
		.r0 = pushed[1],
		.r1 = pushed[2],
		.r2 = pushed[3],
		.r3 = pushed[4],
		.r4 = pushed[5],
		.r5 = pushed[6],
		.r6 = pushed[7],
		.r7 = pushed[8],
		.r8 = pushed[9],
		.r9 = pushed[10],
		.r10 = pushed[11],
		.r11 = pushed[12],
		.usr_sp = (uint32_t)pushed,
		.usr_lr = pushed[13],
		.spsr = read_spsr(),
	};
}

static void save_panic_stack(struct thread_svc_regs *regs)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct tee_ta_session *s;

	if (tee_ta_get_current_session(&s))
		panic("No current session");

	if (tee_mmu_check_access_rights(&to_user_ta_ctx(s->ctx)->uctx,
					TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_WRITE,
					(uaddr_t)regs->r1,
					TA32_CONTEXT_MAX_SIZE)) {
		TAMSG_RAW("");
		TAMSG_RAW("Can't unwind invalid user stack 0x%" PRIxUA,
				(uaddr_t)regs->r1);
		return;
	}

	tsd->abort_type = ABORT_TYPE_TA_PANIC;
	tsd->abort_descr = 0;
	tsd->abort_va = 0;

	save_panic_regs_a32_ta(tsd, (uint32_t *)regs->r1);
}
#else /* CFG_UNWIND */
static void save_panic_stack(struct thread_svc_regs *regs __unused)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	tsd->abort_type = ABORT_TYPE_TA_PANIC;
}
#endif

uint32_t tee_svc_sys_return_helper(uint32_t ret, bool panic,
			uint32_t panic_code, struct thread_svc_regs *regs)
{
	if (panic) {
		TAMSG_RAW("");
		TAMSG_RAW("TA panicked with code 0x%" PRIx32, panic_code);
		save_panic_stack(regs);
	}

	regs->r1 = panic;
	regs->r2 = panic_code;
	regs->lr = (uintptr_t)thread_unwind_user_mode;
	regs->spsr = read_cpsr();
	return ret;
}
#endif /*ARM32*/
#ifdef ARM64
#ifdef CFG_UNWIND
/* Get register values pushed onto the stack by utee_panic() (32-bit TA) */
static void save_panic_regs_a32_ta(struct thread_specific_data *tsd,
				   uint32_t *pushed)
{
	tsd->abort_regs = (struct thread_abort_regs){
		.elr = pushed[0],
		.x0 = pushed[1],
		.x1 = pushed[2],
		.x2 = pushed[3],
		.x3 = pushed[4],
		.x4 = pushed[5],
		.x5 = pushed[6],
		.x6 = pushed[7],
		.x7 = pushed[8],
		.x8 = pushed[9],
		.x9 = pushed[10],
		.x10 = pushed[11],
		.x11 = pushed[12],
		.x13 = (uint64_t)pushed,
		.x14 = pushed[13],
		.spsr = (SPSR_MODE_RW_32 << SPSR_MODE_RW_SHIFT),
	};
}

/* Get register values pushed onto the stack by utee_panic() (64-bit TA) */
static void save_panic_regs_a64_ta(struct thread_specific_data *tsd,
				   uint64_t *pushed)
{
	tsd->abort_regs = (struct thread_abort_regs){
		.x29 = pushed[0],
		.elr = pushed[1],
		.spsr = (SPSR_64_MODE_EL0 << SPSR_64_MODE_EL_SHIFT),
	};
}

static void save_panic_stack(struct thread_svc_regs *regs)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct tee_ta_session *s = NULL;
	struct user_ta_ctx *utc = NULL;

	if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
		panic();

	utc = to_user_ta_ctx(s->ctx);

	if (tee_mmu_check_access_rights(&utc->uctx, TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_WRITE,
					(uaddr_t)regs->x1,
					utc->is_32bit ?
					TA32_CONTEXT_MAX_SIZE :
					TA64_CONTEXT_MAX_SIZE)) {
		TAMSG_RAW("");
		TAMSG_RAW("Can't unwind invalid user stack 0x%" PRIxUA,
				(uaddr_t)regs->x1);
		return;
	}

	tsd->abort_type = ABORT_TYPE_TA_PANIC;
	tsd->abort_descr = 0;
	tsd->abort_va = 0;

	if (utc->is_32bit)
		save_panic_regs_a32_ta(tsd, (uint32_t *)regs->x1);
	else
		save_panic_regs_a64_ta(tsd, (uint64_t *)regs->x1);
}
#else /* CFG_UNWIND */
static void save_panic_stack(struct thread_svc_regs *regs __unused)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	tsd->abort_type = ABORT_TYPE_TA_PANIC;
}
#endif /* CFG_UNWIND */

uint32_t tee_svc_sys_return_helper(uint32_t ret, bool panic,
			uint32_t panic_code, struct thread_svc_regs *regs)
{
	if (panic) {
		TAMSG_RAW("");
		TAMSG_RAW("TA panicked with code 0x%" PRIx32, panic_code);
		save_panic_stack(regs);
	}

	regs->x1 = panic;
	regs->x2 = panic_code;
	regs->elr = (uintptr_t)thread_unwind_user_mode;
	regs->spsr = SPSR_64(SPSR_64_MODE_EL1, SPSR_64_MODE_SP_EL0, 0);
	regs->spsr |= read_daif();
	/*
	 * Regs is the value of stack pointer before calling the SVC
	 * handler.  By the addition matches for the reserved space at the
	 * beginning of el0_sync_svc(). This prepares the stack when
	 * returning to thread_unwind_user_mode instead of a normal
	 * exception return.
	 */
	regs->sp_el0 = (uint64_t)(regs + 1);
	return ret;
}
#endif /*ARM64*/
