// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2022, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <assert.h>
#include <kernel/abort.h>
#include <kernel/arch_scall.h>
#include <kernel/ldelf_syscalls.h>
#include <kernel/scall.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <kernel/trace_ta.h>
#include <kernel/user_access.h>
#include <kernel/user_ta.h>
#include <ldelf.h>
#include <mm/vm.h>
#include <speculation_barrier.h>
#include <tee/svc_cache.h>
#include <tee_syscall_numbers.h>
#include <tee/tee_svc_cryp.h>
#include <tee/tee_svc.h>
#include <tee/tee_svc_storage.h>
#include <trace.h>
#include <util.h>

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
static const struct syscall_entry tee_syscall_table[] = {
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

/*
 * The ldelf return, log, panic syscalls have the same functionality and syscall
 * number as the user TAs'. To avoid unnecessary code duplication, the ldelf SVC
 * handler doesn't implement separate functions for these.
 */
static const struct syscall_entry ldelf_syscall_table[] = {
	SYSCALL_ENTRY(syscall_sys_return),
	SYSCALL_ENTRY(syscall_log),
	SYSCALL_ENTRY(syscall_panic),
	SYSCALL_ENTRY(ldelf_syscall_map_zi),
	SYSCALL_ENTRY(ldelf_syscall_unmap),
	SYSCALL_ENTRY(ldelf_syscall_open_bin),
	SYSCALL_ENTRY(ldelf_syscall_close_bin),
	SYSCALL_ENTRY(ldelf_syscall_map_bin),
	SYSCALL_ENTRY(ldelf_syscall_copy_from_bin),
	SYSCALL_ENTRY(ldelf_syscall_set_prot),
	SYSCALL_ENTRY(ldelf_syscall_remap),
	SYSCALL_ENTRY(ldelf_syscall_gen_rnd_num),
};

#ifdef TRACE_SYSCALLS
static void trace_syscall(size_t num)
{
	if (num == TEE_SCN_RETURN || num == TEE_SCN_LOG || num > TEE_SCN_MAX)
		return;
	FMSG("syscall #%zu (%s)", num, tee_syscall_table[num].name);
}
#else
static void trace_syscall(size_t num __unused)
{
}
#endif

#ifdef CFG_SYSCALL_FTRACE
static void __noprof ftrace_syscall_enter(size_t num)
{
	struct ts_session *s = NULL;

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
	if (s && s->fbuf)
		s->fbuf->syscall_trace_enabled = true;
}

static void __noprof ftrace_syscall_leave(void)
{
	struct ts_session *s = TAILQ_FIRST(&thread_get_tsd()->sess_stack);

	if (s && s->fbuf)
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

static syscall_t get_tee_syscall_func(size_t num)
{
	/* Cast away const */
	struct syscall_entry *sc_table = (void *)tee_syscall_table;

	static_assert(ARRAY_SIZE(tee_syscall_table) == (TEE_SCN_MAX + 1));

	if (num > TEE_SCN_MAX)
		return (syscall_t)syscall_not_supported;

	return load_no_speculate(&sc_table[num].fn, &sc_table[0].fn,
				 &sc_table[TEE_SCN_MAX].fn + 1);
}

bool scall_handle_user_ta(struct thread_scall_regs *regs)
{
	size_t scn = 0;
	size_t max_args = 0;
	syscall_t scf = NULL;

	bb_reset();
	scall_get_max_args(regs, &scn, &max_args);

	trace_syscall(scn);

	if (max_args > TEE_SVC_MAX_ARGS) {
		DMSG("Too many arguments for SCN %zu (%zu)", scn, max_args);
		scall_set_retval(regs, TEE_ERROR_GENERIC);
		return true; /* return to user mode */
	}

	scf = get_tee_syscall_func(scn);

	ftrace_syscall_enter(scn);

	scall_set_retval(regs, scall_do_call(regs, scf));

	ftrace_syscall_leave();

	/*
	 * Return true if we're to return to user mode,
	 * thread_scall_handler() will take care of the rest.
	 */
	return scn != TEE_SCN_RETURN && scn != TEE_SCN_PANIC;
}

static syscall_t get_ldelf_syscall_func(size_t num)
{
	/* Cast away const */
	struct syscall_entry *sc_table = (void *)ldelf_syscall_table;

	COMPILE_TIME_ASSERT(ARRAY_SIZE(ldelf_syscall_table) ==
			    (LDELF_SCN_MAX + 1));

	if (num > LDELF_SCN_MAX)
		return (syscall_t)syscall_not_supported;

	return load_no_speculate(&sc_table[num].fn, &sc_table[0].fn,
				 &sc_table[LDELF_SCN_MAX].fn + 1);
}

bool scall_handle_ldelf(struct thread_scall_regs *regs)
{
	size_t scn = 0;
	size_t max_args = 0;
	syscall_t scf = NULL;

	bb_reset();
	scall_get_max_args(regs, &scn, &max_args);

	trace_syscall(scn);

	if (max_args > TEE_SVC_MAX_ARGS) {
		DMSG("Too many arguments for SCN %zu (%zu)", scn, max_args);
		scall_set_retval(regs, TEE_ERROR_GENERIC);
		return true; /* return to user mode */
	}

	scf = get_ldelf_syscall_func(scn);

	ftrace_syscall_enter(scn);

	scall_set_retval(regs, scall_do_call(regs, scf));

	ftrace_syscall_leave();

	/*
	 * Return true if we're to return to user mode,
	 * thread_scall_handler() will take care of the rest.
	 */
	return scn != LDELF_RETURN && scn != LDELF_PANIC;
}

uint32_t scall_sys_return_helper(uint32_t ret, bool panic, uint32_t panic_code,
				 struct thread_scall_regs *regs)
{
	if (panic) {
		TAMSG_RAW("");
		TAMSG_RAW("TA panicked with code 0x%" PRIx32, panic_code);
		scall_save_panic_stack(regs);
	}

	scall_set_sys_return_regs(regs, panic, panic_code);

	return ret;
}
