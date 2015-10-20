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
#include <kernel/thread.h>
#include <tee/tee_svc.h>
#include <tee/arch_svc.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc_storage.h>
#include <tee/se/svc.h>
#include <tee_syscall_numbers.h>
#include <util.h>
#include "arch_svc_private.h"
#include <assert.h>
#include <trace.h>
#include <kernel/misc.h>
#include <kernel/trace_ta.h>

static const syscall_t tee_svc_syscall_table[] = {
	(syscall_t)syscall_sys_return,
	(syscall_t)syscall_log,
	(syscall_t)syscall_panic,
	(syscall_t)syscall_dummy,
	(syscall_t)syscall_dummy_7args,
	(syscall_t)syscall_get_property,
	(syscall_t)syscall_open_ta_session,
	(syscall_t)syscall_close_ta_session,
	(syscall_t)syscall_invoke_ta_command,
	(syscall_t)syscall_check_access_rights,
	(syscall_t)syscall_get_cancellation_flag,
	(syscall_t)syscall_unmask_cancellation,
	(syscall_t)syscall_mask_cancellation,
	(syscall_t)syscall_wait,
	(syscall_t)syscall_get_time,
	(syscall_t)syscall_set_ta_time,
	(syscall_t)syscall_cryp_state_alloc,
	(syscall_t)syscall_cryp_state_copy,
	(syscall_t)syscall_cryp_state_free,
	(syscall_t)syscall_hash_init,
	(syscall_t)syscall_hash_update,
	(syscall_t)syscall_hash_final,
	(syscall_t)syscall_cipher_init,
	(syscall_t)syscall_cipher_update,
	(syscall_t)syscall_cipher_final,
	(syscall_t)syscall_cryp_obj_get_info,
	(syscall_t)syscall_cryp_obj_restrict_usage,
	(syscall_t)syscall_cryp_obj_get_attr,
	(syscall_t)syscall_cryp_obj_alloc,
	(syscall_t)syscall_cryp_obj_close,
	(syscall_t)syscall_cryp_obj_reset,
	(syscall_t)syscall_cryp_obj_populate,
	(syscall_t)syscall_cryp_obj_copy,
	(syscall_t)syscall_cryp_derive_key,
	(syscall_t)syscall_cryp_random_number_generate,
	(syscall_t)syscall_authenc_init,
	(syscall_t)syscall_authenc_update_aad,
	(syscall_t)syscall_authenc_update_payload,
	(syscall_t)syscall_authenc_enc_final,
	(syscall_t)syscall_authenc_dec_final,
	(syscall_t)syscall_asymm_operate,
	(syscall_t)syscall_asymm_verify,
	(syscall_t)syscall_storage_obj_open,
	(syscall_t)syscall_storage_obj_create,
	(syscall_t)syscall_storage_obj_del,
	(syscall_t)syscall_storage_obj_rename,
	(syscall_t)syscall_storage_alloc_enum,
	(syscall_t)syscall_storage_free_enum,
	(syscall_t)syscall_storage_reset_enum,
	(syscall_t)syscall_storage_start_enum,
	(syscall_t)syscall_storage_next_enum,
	(syscall_t)syscall_storage_obj_read,
	(syscall_t)syscall_storage_obj_write,
	(syscall_t)syscall_storage_obj_trunc,
	(syscall_t)syscall_storage_obj_seek,
	(syscall_t)syscall_obj_generate_key,
	(syscall_t)syscall_se_service_open,
	(syscall_t)syscall_se_service_close,
	(syscall_t)syscall_se_service_get_readers,
	(syscall_t)syscall_se_reader_get_prop,
	(syscall_t)syscall_se_reader_get_name,
	(syscall_t)syscall_se_reader_open_session,
	(syscall_t)syscall_se_reader_close_sessions,
	(syscall_t)syscall_se_session_is_closed,
	(syscall_t)syscall_se_session_get_atr,
	(syscall_t)syscall_se_session_open_channel,
	(syscall_t)syscall_se_session_close,
	(syscall_t)syscall_se_channel_select_next,
	(syscall_t)syscall_se_channel_get_select_resp,
	(syscall_t)syscall_se_channel_transmit,
	(syscall_t)syscall_se_channel_close,
	(syscall_t)syscall_cache_operation,
};

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
	*scn = regs->x7;
	*max_args = regs->x6;
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

void tee_svc_handler(struct thread_svc_regs *regs)
{
	size_t scn;
	size_t max_args;
	syscall_t scf;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(tee_svc_syscall_table) ==
				(TEE_SCN_MAX + 1));

	/* Restore IRQ which are disabled on exception entry */
	thread_restore_irq();

	get_scn_max_args(regs, &scn, &max_args);

#if (TRACE_LEVEL == TRACE_FLOW) && defined(CFG_TEE_CORE_TA_TRACE)
	tee_svc_trace_syscall(scn);
#endif

	if (max_args > TEE_SVC_MAX_ARGS) {
		DMSG("Too many arguments for SCN %zu (%zu)", scn, max_args);
		set_svc_retval(regs, TEE_ERROR_GENERIC);
		return;
	}

	if (scn > TEE_SCN_MAX)
		scf = syscall_nocall;
	else
		scf = tee_svc_syscall_table[scn];

	set_svc_retval(regs, tee_svc_do_call(regs, scf));
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
	return ret;
}
#endif /*ARM64*/
