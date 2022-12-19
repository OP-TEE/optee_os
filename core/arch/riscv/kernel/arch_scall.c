// SPDX-License-Identifier: BSD-2-Clause
/*
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

static void save_panic_regs_rv_ta(struct thread_specific_data *tsd,
				  unsigned long *pushed)
{
	tsd->abort_regs = (struct thread_abort_regs){
		.ra = pushed[0],
		.sp = (unsigned long)pushed,
		.gp = pushed[1],
		.tp = pushed[2],
		.t0 = pushed[3],
		.t1 = pushed[4],
		.t2 = pushed[5],
		.s0 = pushed[6],
		.s1 = pushed[7],
		.a0 = pushed[8],
		.a1 = pushed[9],
		.a2 = pushed[10],
		.a3 = pushed[11],
		.a4 = pushed[12],
		.a5 = pushed[13],
		.a6 = pushed[14],
		.a7 = pushed[15],
		.s2 = pushed[16],
		.s3 = pushed[17],
		.s4 = pushed[18],
		.s5 = pushed[19],
		.s6 = pushed[20],
		.s7 = pushed[21],
		.s8 = pushed[22],
		.s9 = pushed[23],
		.s10 = pushed[24],
		.s11 = pushed[25],
		.t3 = pushed[26],
		.t4 = pushed[27],
		.t5 = pushed[28],
		.t6 = pushed[29],
		.status = read_csr(CSR_XSTATUS),
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
