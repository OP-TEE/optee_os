// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2022, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <kernel/abort.h>
#include <kernel/scall.h>
#include <kernel/thread.h>
#include <kernel/trace_ta.h>
#include <kernel/user_access.h>
#include <kernel/user_ta.h>
#include <mm/vm.h>
#include <types_ext.h>

#define TA32_CONTEXT_MAX_SIZE		(14 * sizeof(uint32_t))
#define TA64_CONTEXT_MAX_SIZE		(2 * sizeof(uint64_t))

#ifdef CFG_UNWIND
#ifdef ARM32
/* Get register values pushed onto the stack by _utee_panic() */
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

void scall_save_panic_stack(struct thread_scall_regs *regs)
{
	struct thread_specific_data *tsd = thread_get_tsd();
	struct ts_session *s = ts_get_current_session();
	struct user_ta_ctx *utc = to_user_ta_ctx(s->ctx);

	tsd->abort_type = ABORT_TYPE_USER_MODE_PANIC;
	tsd->abort_descr = 0;
	tsd->abort_va = 0;

	if (vm_check_access_rights(&utc->uctx,
				   TEE_MEMORY_ACCESS_READ |
				   TEE_MEMORY_ACCESS_WRITE,
				   (uaddr_t)regs->r1, TA32_CONTEXT_MAX_SIZE)) {
		TAMSG_RAW("");
		TAMSG_RAW("Can't unwind invalid user stack 0x%"PRIxUA,
			  (uaddr_t)regs->r1);
		return;
	}

	save_panic_regs_a32_ta(tsd, (uint32_t *)regs->r1);
}
#endif /*ARM32*/

#ifdef ARM64
/* Get register values pushed onto the stack by _utee_panic() (32-bit TA) */
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

/* Get register values pushed onto the stack by _utee_panic() (64-bit TA) */
static void save_panic_regs_a64_ta(struct thread_specific_data *tsd,
				   uint64_t *pushed)
{
	TEE_Result res = TEE_SUCCESS;
	uint64_t x29 = 0;
	uint64_t elr = 0;

	res = GET_USER_SCALAR(x29, &pushed[0]);
	if (res)
		x29 = 0;

	res = GET_USER_SCALAR(elr, &pushed[1]);
	if (res)
		elr = 0;

	tsd->abort_regs = (struct thread_abort_regs){
		.x29 = x29,
		.elr = elr,
		.spsr = (SPSR_64_MODE_EL0 << SPSR_64_MODE_EL_SHIFT),
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
				   (uaddr_t)regs->x1,
				   utc->uctx.is_32bit ?
				   TA32_CONTEXT_MAX_SIZE :
				   TA64_CONTEXT_MAX_SIZE)) {
		TAMSG_RAW("");
		TAMSG_RAW("Can't unwind invalid user stack 0x%"PRIxUA,
			  (uaddr_t)regs->x1);
		return;
	}

	tsd->abort_type = ABORT_TYPE_USER_MODE_PANIC;
	tsd->abort_descr = 0;
	tsd->abort_va = 0;

	if (utc->uctx.is_32bit)
		save_panic_regs_a32_ta(tsd, (uint32_t *)regs->x1);
	else
		save_panic_regs_a64_ta(tsd, (uint64_t *)regs->x1);
}
#endif /*ARM64*/

#else /* CFG_UNWIND */
void scall_save_panic_stack(struct thread_scall_regs *regs __unused)
{
	struct thread_specific_data *tsd = thread_get_tsd();

	tsd->abort_type = ABORT_TYPE_USER_MODE_PANIC;
}
#endif /* CFG_UNWIND */
