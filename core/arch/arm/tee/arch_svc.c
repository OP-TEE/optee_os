/*
 * Copyright (c) 2014, Linaro Limited
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

#include <arm.h>
#include <assert.h>
#include <kernel/misc.h>
#include <kernel/thread.h>
#include <kernel/trace_ta.h>
#include <tee/tee_svc.h>
#include <tee/arch_svc.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc_storage.h>
#include <tee/se/svc.h>
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
	SYSCALL_ENTRY(syscall_se_service_open),
	SYSCALL_ENTRY(syscall_se_service_close),
	SYSCALL_ENTRY(syscall_se_service_get_readers),
	SYSCALL_ENTRY(syscall_se_reader_get_prop),
	SYSCALL_ENTRY(syscall_se_reader_get_name),
	SYSCALL_ENTRY(syscall_se_reader_open_session),
	SYSCALL_ENTRY(syscall_se_reader_close_sessions),
	SYSCALL_ENTRY(syscall_se_session_is_closed),
	SYSCALL_ENTRY(syscall_se_session_get_atr),
	SYSCALL_ENTRY(syscall_se_session_open_channel),
	SYSCALL_ENTRY(syscall_se_session_close),
	SYSCALL_ENTRY(syscall_se_channel_select_next),
	SYSCALL_ENTRY(syscall_se_channel_get_select_resp),
	SYSCALL_ENTRY(syscall_se_channel_transmit),
	SYSCALL_ENTRY(syscall_se_channel_close),
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

	COMPILE_TIME_ASSERT(ARRAY_SIZE(tee_svc_syscall_table) ==
				(TEE_SCN_MAX + 1));

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
		scf = syscall_not_supported;
	else
		scf = tee_svc_syscall_table[scn].fn;

	set_svc_retval(regs, tee_svc_do_call(regs, scf));

	if (scn != TEE_SCN_RETURN) {
		/* We're about to switch back to user mode */
		tee_ta_update_session_utime_resume();
	}
}

#ifdef ARM32
uint32_t tee_svc_sys_return_helper(uint32_t ret, bool panic,
			uint32_t panic_code, struct thread_svc_regs *regs)
{
	if (panic) {
		TAMSG("TA panicked with code 0x%x usr_sp 0x%x usr_lr 0x%x",
		      panic_code, read_mode_sp(CPSR_MODE_SYS),
		      read_mode_lr(CPSR_MODE_SYS));
	}
	regs->r1 = panic;
	regs->r2 = panic_code;
	regs->lr = (uintptr_t)thread_unwind_user_mode;
	regs->spsr = read_cpsr();
	return ret;
}
#endif /*ARM32*/
#ifdef ARM64
uint32_t tee_svc_sys_return_helper(uint32_t ret, bool panic,
			uint32_t panic_code, struct thread_svc_regs *regs)
{
	if (panic) {
		TAMSG("TA panicked with code 0x%x usr_sp 0x%" PRIx64 " usr_lr 0x%" PRIx64,
			panic_code, regs->x13, regs->x14);
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
