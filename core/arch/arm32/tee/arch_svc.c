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

#include <arm32.h>
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

static const tee_svc_func tee_svc_syscall_table[] = {
	(tee_svc_func)tee_svc_sys_return,
	(tee_svc_func)tee_svc_sys_log,
	(tee_svc_func)tee_svc_sys_panic,
	(tee_svc_func)tee_svc_sys_dummy,
	(tee_svc_func)tee_svc_sys_dummy_7args,
	(tee_svc_func)tee_svc_sys_get_property,
	(tee_svc_func)tee_svc_open_ta_session,
	(tee_svc_func)tee_svc_close_ta_session,
	(tee_svc_func)tee_svc_invoke_ta_command,
	(tee_svc_func)tee_svc_check_access_rights,
	(tee_svc_func)tee_svc_get_cancellation_flag,
	(tee_svc_func)tee_svc_unmask_cancellation,
	(tee_svc_func)tee_svc_mask_cancellation,
	(tee_svc_func)tee_svc_wait,
	(tee_svc_func)tee_svc_get_time,
	(tee_svc_func)tee_svc_set_ta_time,
	(tee_svc_func)tee_svc_cryp_state_alloc,
	(tee_svc_func)tee_svc_cryp_state_copy,
	(tee_svc_func)tee_svc_cryp_state_free,
	(tee_svc_func)tee_svc_hash_init,
	(tee_svc_func)tee_svc_hash_update,
	(tee_svc_func)tee_svc_hash_final,
	(tee_svc_func)tee_svc_cipher_init,
	(tee_svc_func)tee_svc_cipher_update,
	(tee_svc_func)tee_svc_cipher_final,
	(tee_svc_func)tee_svc_cryp_obj_get_info,
	(tee_svc_func)tee_svc_cryp_obj_restrict_usage,
	(tee_svc_func)tee_svc_cryp_obj_get_attr,
	(tee_svc_func)tee_svc_cryp_obj_alloc,
	(tee_svc_func)tee_svc_cryp_obj_close,
	(tee_svc_func)tee_svc_cryp_obj_reset,
	(tee_svc_func)tee_svc_cryp_obj_populate,
	(tee_svc_func)tee_svc_cryp_obj_copy,
	(tee_svc_func)tee_svc_cryp_derive_key,
	(tee_svc_func)tee_svc_cryp_random_number_generate,
	(tee_svc_func)tee_svc_authenc_init,
	(tee_svc_func)tee_svc_authenc_update_aad,
	(tee_svc_func)tee_svc_authenc_update_payload,
	(tee_svc_func)tee_svc_authenc_enc_final,
	(tee_svc_func)tee_svc_authenc_dec_final,
	(tee_svc_func)tee_svc_asymm_operate,
	(tee_svc_func)tee_svc_asymm_verify,
	(tee_svc_func)tee_svc_storage_obj_open,
	(tee_svc_func)tee_svc_storage_obj_create,
	(tee_svc_func)tee_svc_storage_obj_del,
	(tee_svc_func)tee_svc_storage_obj_rename,
	(tee_svc_func)tee_svc_storage_alloc_enum,
	(tee_svc_func)tee_svc_storage_free_enum,
	(tee_svc_func)tee_svc_storage_reset_enum,
	(tee_svc_func)tee_svc_storage_start_enum,
	(tee_svc_func)tee_svc_storage_next_enum,
	(tee_svc_func)tee_svc_storage_obj_read,
	(tee_svc_func)tee_svc_storage_obj_write,
	(tee_svc_func)tee_svc_storage_obj_trunc,
	(tee_svc_func)tee_svc_storage_obj_seek,
	(tee_svc_func)tee_svc_obj_generate_key,
	(tee_svc_func)tee_svc_se_service_open,
	(tee_svc_func)tee_svc_se_service_close,
	(tee_svc_func)tee_svc_se_service_get_readers,
	(tee_svc_func)tee_svc_se_reader_get_prop,
	(tee_svc_func)tee_svc_se_reader_get_name,
	(tee_svc_func)tee_svc_se_reader_open_session,
	(tee_svc_func)tee_svc_se_reader_close_sessions,
	(tee_svc_func)tee_svc_se_session_is_closed,
	(tee_svc_func)tee_svc_se_session_get_atr,
	(tee_svc_func)tee_svc_se_session_open_channel,
	(tee_svc_func)tee_svc_se_session_close,
	(tee_svc_func)tee_svc_se_channel_select_next,
	(tee_svc_func)tee_svc_se_channel_get_select_resp,
	(tee_svc_func)tee_svc_se_channel_transmit,
	(tee_svc_func)tee_svc_se_channel_close,
	(tee_svc_func)tee_svc_cache_operation,
};

void tee_svc_handler(struct thread_svc_regs *regs)
{
	const uint32_t scn = regs->r7;
	tee_svc_func scf;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(tee_svc_syscall_table) ==
				(TEE_SCN_MAX + 1));

	/* Restore IRQ which are disabled on exception entry */
	thread_restore_irq();

#if (CFG_TRACE_LEVEL == TRACE_FLOW) && (!defined(CFG_TEE_CORE_NO_TA_TRACE))
	tee_svc_trace_syscall(scn);
#endif

	if (regs->r6 > TEE_SVC_MAX_ARGS) {
		DMSG("Too many arguments for SCN %u (%u)", scn, regs->r6);
		regs->r0 = TEE_ERROR_GENERIC;
		return;
	}

	if (scn > TEE_SCN_MAX)
		scf = tee_svc_sys_nocall;
	else
		scf = tee_svc_syscall_table[scn];

	regs->r0 = tee_svc_do_call(regs, scf);
}

uint32_t tee_svc_sys_return_helper(uint32_t ret, bool panic,
			uint32_t panic_code, struct thread_svc_regs *regs)
{
	if (panic) {
		TAMSG("TA panicked with code 0x%x usr_sp 0x%x usr_lr 0x%x",
			panic_code, read_usr_sp(), read_usr_lr());
	}
	regs->r1 = panic;
	regs->r2 = panic_code;
	regs->lr = (uintptr_t)tee_svc_unwind_enter_user_mode;
	regs->spsr = read_cpsr();
	return ret;
}
