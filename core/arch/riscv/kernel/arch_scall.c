// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022-2023 NXP
 * Copyright (c) 2014-2022, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <kernel/abort.h>
#include <kernel/scall.h>
#include <kernel/thread.h>
#include <kernel/trace_ta.h>
#include <kernel/user_ta.h>
#include <mm/vm.h>
#include <riscv.h>
#include <types_ext.h>

#define TA_CONTEXT_MAX_SIZE	(RISCV_XLEN_BYTES * 32)

#ifdef CFG_UNWIND

/* Get register values pushed onto the stack by _utee_panic() */
static void save_panic_regs_rv_ta(struct thread_specific_data *tsd,
				  unsigned long *pushed)
{
	tsd->abort_regs = (struct thread_abort_regs){
		.sp = (unsigned long)pushed,
#if defined(RV32)
		.s0 = pushed[2],
		.epc = pushed[3],
#elif defined(RV64)
		.s0 = pushed[0],
		.epc = pushed[1],
#endif
	};
}

void scall_save_panic_stack(struct thread_scall_regs *regs)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct ts_session *s = ts_get_current_session();
	struct user_ta_ctx *utc = to_user_ta_ctx(s->ctx);

	if (vm_check_access_rights(&utc->uctx,
				   TEE_MEMORY_ACCESS_READ |
				   TEE_MEMORY_ACCESS_WRITE,
				   (uaddr_t)regs->a1,
				   TA_CONTEXT_MAX_SIZE)) {
		TAMSG_RAW("");
		TAMSG_RAW("Can't unwind invalid user stack 0x%"PRIxUA,
			  (uaddr_t)regs->a1);
		return;
	}

	tsd->abort_type = ABORT_TYPE_USER_MODE_PANIC;
	tsd->abort_descr = 0;
	tsd->abort_va = 0;

	save_panic_regs_rv_ta(tsd, (unsigned long *)regs->a1);
}

#else /* CFG_UNWIND */
void scall_save_panic_stack(struct thread_scall_regs *regs __unused)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	tsd->abort_type = ABORT_TYPE_USER_MODE_PANIC;
}
#endif /* CFG_UNWIND */
