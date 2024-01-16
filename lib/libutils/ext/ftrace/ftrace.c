// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Linaro Limited
 */

/*
 * APIs defined in this file are required to use __noprof attribute to
 * avoid any circular dependency during profiling. So this requirement
 * prohibits these APIs to use standard library APIs as those can be
 * profiled too.
 */

#include <assert.h>
#include <types_ext.h>
#include <user_ta_header.h>
#if defined(__KERNEL__)
#if defined(ARM32) || defined(ARM64)
#include <arm.h>
#elif defined(RV32) || defined(RV64)
#include <riscv.h>
#endif
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#else
#if defined(ARM32) || defined(ARM64)
#include <arm_user_sysreg.h>
#elif defined(RV32) || defined(RV64)
#include <riscv_user_sysreg.h>
#endif
#include <setjmp.h>
#include <utee_syscalls.h>
#endif
#include "ftrace.h"

static __noprof struct ftrace_buf *get_fbuf(void)
{
#if defined(__KERNEL__)
	short int ct = thread_get_id_may_fail();
	struct ts_session *s = NULL;
	struct thread_specific_data *tsd = NULL;

	if (ct == -1)
		return NULL;

	if (!(core_mmu_user_va_range_is_defined() &&
	      core_mmu_user_mapping_is_active()))
		return NULL;

	tsd = thread_get_tsd();
	s = TAILQ_FIRST(&tsd->sess_stack);

	if (!s || tsd->ctx != s->ctx)
		return NULL;

	if (!is_ta_ctx(s->ctx) || to_ta_ctx(s->ctx)->panicked)
		return NULL;

	if (s->fbuf && s->fbuf->syscall_trace_enabled &&
	    !s->fbuf->syscall_trace_suspended)
		return s->fbuf;
	else
		return NULL;
#else
	return &__ftrace_buf_start;
#endif
}

static void __noprof add_elem(struct ftrace_buf *fbuf, uint8_t level,
			       uint64_t val)
{
	uint64_t *elem = NULL;
	size_t idx = fbuf->curr_idx;

	/* Make sure the topmost byte doesn't contain useful information */
	assert(!(val >> 56));

	elem = (uint64_t *)((vaddr_t)fbuf + fbuf->buf_off) + idx;
	*elem = SHIFT_U64(level, 56) | val;

	idx++;
	if ((idx + 1) * sizeof(*elem) > fbuf->max_size) {
		idx = 0;
		fbuf->overflow = true;
	}

	fbuf->curr_idx = idx;
}

void __noprof ftrace_enter(unsigned long pc, unsigned long *lr)
{
	uint64_t now = barrier_read_counter_timer();
	struct ftrace_buf *fbuf = get_fbuf();

	if (!fbuf || !fbuf->buf_off || !fbuf->max_size)
		return;

	add_elem(fbuf, fbuf->ret_idx + 1, pc);

	if (fbuf->ret_idx < FTRACE_RETFUNC_DEPTH) {
		fbuf->ret_stack[fbuf->ret_idx] = *lr;
		fbuf->begin_time[fbuf->ret_idx] = now;
		fbuf->ret_idx++;
	} else {
		/*
		 * This scenario isn't expected as function call depth
		 * shouldn't be more than FTRACE_RETFUNC_DEPTH.
		 */
#if defined(__KERNEL__)
		panic();
#else
		_utee_panic(0);
#endif
	}

	*lr = (unsigned long)&__ftrace_return;
}

unsigned long __noprof ftrace_return(void)
{
	uint64_t now = barrier_read_counter_timer();
	struct ftrace_buf *fbuf = get_fbuf();
	uint64_t start = 0;
	uint64_t elapsed = 0;

	/* Check for valid return index */
	if (!fbuf || !fbuf->ret_idx || fbuf->ret_idx > FTRACE_RETFUNC_DEPTH)
		return 0;

	fbuf->ret_idx--;
	start = fbuf->begin_time[fbuf->ret_idx];
	elapsed = (now - start) * 1000000000 / read_cntfrq();
	add_elem(fbuf, 0, elapsed);

	return fbuf->ret_stack[fbuf->ret_idx];
}

#if !defined(__KERNEL__)
void __noprof ftrace_longjmp(unsigned int *ret_idx)
{
	while (__ftrace_buf_start.ret_idx > *ret_idx)
		ftrace_return();
}

void __noprof ftrace_setjmp(unsigned int *ret_idx)
{
	*ret_idx = __ftrace_buf_start.ret_idx;
}
#endif
