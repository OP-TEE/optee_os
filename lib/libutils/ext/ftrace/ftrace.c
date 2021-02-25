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
#include <user_ta_header.h>
#if defined(__KERNEL__)
#include <arm.h>
#include <kernel/panic.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/thread.h>
#include <mm/core_mmu.h>
#else
#include <arm_user_sysreg.h>
#include <setjmp.h>
#include <utee_syscalls.h>
#endif
#include "ftrace.h"

#define DURATION_MAX_LEN		16

static const char hex_str[] = "0123456789abcdef";

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

	if (s->fbuf && s->fbuf->syscall_trace_enabled &&
	    !s->fbuf->syscall_trace_suspended)
		return s->fbuf;
	else
		return NULL;
#else
	return &__ftrace_buf_start;
#endif
}

#if defined(_CFG_FTRACE_BUF_WHEN_FULL_shift)

/*
 * This API shifts/moves ftrace buffer to create space for new dump
 * in case the buffer size falls short of actual dump.
 */
static bool __noprof fbuf_make_room(struct ftrace_buf *fbuf, size_t size)
{
	char *dst = (char *)fbuf + fbuf->buf_off;
	const char *src = (char *)fbuf + fbuf->buf_off + size;
	size_t n = 0;

	fbuf->curr_size -= size;

	for (n = 0; n < fbuf->curr_size; n++)
		dst[n] = src[n];

	return true;
}

#elif defined(_CFG_FTRACE_BUF_WHEN_FULL_wrap)

/* Makes room in the trace buffer by discarding the previously recorded data. */
static bool __noprof fbuf_make_room(struct ftrace_buf *fbuf,
				    size_t size)
{
	if (fbuf->buf_off + size > fbuf->max_size)
		return false;

	fbuf->curr_size = 0;

	return true;
}

#elif defined(_CFG_FTRACE_BUF_WHEN_FULL_stop)

static bool __noprof fbuf_make_room(struct ftrace_buf *fbuf __unused,
				    size_t size __unused)
{
	return false;
}

#else
#error CFG_FTRACE_BUF_WHEN_FULL value not supported
#endif

static size_t __noprof to_func_enter_fmt(char *buf, uint32_t ret_idx,
					 unsigned long pc)
{
	char *str = buf;
	uint32_t addr_size = 2 * sizeof(unsigned long);
	uint32_t i = 0;

	for (i = 0; i < (DURATION_MAX_LEN + ret_idx); i++)
		if (i == (DURATION_MAX_LEN - 2))
			*str++ = '|';
		else
			*str++ = ' ';

	*str++ = '0';
	*str++ = 'x';

	for (i = 0; i < addr_size; i++)
		*str++ = hex_str[(pc >> 4 * (addr_size - i - 1)) & 0xf];

	*str++ = '(';
	*str++ = ')';
	*str++ = ' ';
	*str++ = '{';
	*str++ = '\n';
	*str = '\0';

	return str - buf;
}

void __noprof ftrace_enter(unsigned long pc, unsigned long *lr)
{
	struct ftrace_buf *fbuf = NULL;
	size_t dump_size = 0;
	bool full = false;

	fbuf = get_fbuf();

	if (!fbuf || !fbuf->buf_off || !fbuf->max_size)
		return;

	dump_size = DURATION_MAX_LEN + fbuf->ret_idx +
			(2 * sizeof(unsigned long)) + 8;

	/*
	 * Check if we have enough space in ftrace buffer. If not then try to
	 * make room.
	 */
	full = (fbuf->curr_size + dump_size) > fbuf->max_size;
	if (full)
		full = !fbuf_make_room(fbuf, dump_size);

	if (!full)
		fbuf->curr_size += to_func_enter_fmt((char *)fbuf +
						     fbuf->buf_off +
						     fbuf->curr_size,
						     fbuf->ret_idx,
						     pc);

	if (fbuf->ret_idx < FTRACE_RETFUNC_DEPTH) {
		fbuf->ret_stack[fbuf->ret_idx] = *lr;
		fbuf->begin_time[fbuf->ret_idx] = barrier_read_counter_timer();
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

static void __noprof ftrace_duration(char *buf, uint64_t start, uint64_t end)
{
	uint32_t max_us = CFG_FTRACE_US_MS;
	uint32_t cntfrq = read_cntfrq();
	uint64_t ticks = end - start;
	uint32_t ms = 0;
	uint32_t us = 0;
	uint32_t ns = 0;
	uint32_t frac = 0;
	uint32_t in = 0;
	char unit = 'u';
	int i = 0;

	ticks = ticks * 1000000000 / cntfrq;
	us = ticks / 1000;
	ns = ticks % 1000;

	if (max_us && us >= max_us) {
		/* Display value in milliseconds */
		unit = 'm';
		ms = us / 1000;
		us = us % 1000;
		frac = us;
		in = ms;
	} else {
		/* Display value in microseconds */
		frac = ns;
		in = us;
	}

	*buf-- = 's';
	*buf-- = unit;
	*buf-- = ' ';

	COMPILE_TIME_ASSERT(DURATION_MAX_LEN == 16);
	if (in > 999999) {
		/* Not enough space to print the value */
		for (i = 0; i < 10; i++)
			*buf-- = '-';
		return;
	}

	for (i = 0; i < 3; i++) {
		*buf-- = hex_str[frac % 10];
		frac /= 10;
	}

	*buf-- = '.';

	while (in) {
		*buf-- = hex_str[in % 10];
		in /= 10;
	}
}

unsigned long __noprof ftrace_return(void)
{
	struct ftrace_buf *fbuf = NULL;
	size_t dump_size = 0;
	char *curr_buf = NULL;
	char *dur_loc = NULL;
	uint32_t i = 0;

	fbuf = get_fbuf();

	/* Check for valid return index */
	if (fbuf && fbuf->ret_idx && fbuf->ret_idx <= FTRACE_RETFUNC_DEPTH)
		fbuf->ret_idx--;
	else
		return 0;

	curr_buf = (char *)fbuf + fbuf->buf_off + fbuf->curr_size;

	/*
	 * Check for '{' symbol as it represents if it is an exit from current
	 * or nested function. If exit is from current function, than exit dump
	 * via ';' symbol else exit dump via '}' symbol.
	 */
	if (*(curr_buf - 2) == '{') {
		*(curr_buf - 3) = ';';
		*(curr_buf - 2) = '\n';
		*(curr_buf - 1) = '\0';
		fbuf->curr_size -= 1;

		dur_loc = curr_buf - (fbuf->ret_idx +
				      (2 * sizeof(unsigned long)) + 11);
		ftrace_duration(dur_loc, fbuf->begin_time[fbuf->ret_idx],
				barrier_read_counter_timer());
	} else {
		bool full = false;

		dump_size = DURATION_MAX_LEN + fbuf->ret_idx + 3;
		full = (fbuf->curr_size + dump_size) > fbuf->max_size;
		if (full)
			full = !fbuf_make_room(fbuf, dump_size);

		if (!full) {
			curr_buf = (char *)fbuf + fbuf->buf_off +
				   fbuf->curr_size;

			for (i = 0; i < (DURATION_MAX_LEN + fbuf->ret_idx); i++)
				if (i == (DURATION_MAX_LEN - 2))
					*curr_buf++ = '|';
				else
					*curr_buf++ = ' ';

			*curr_buf++ = '}';
			*curr_buf++ = '\n';
			*curr_buf = '\0';

			fbuf->curr_size += dump_size - 1;

			dur_loc = curr_buf - fbuf->ret_idx - 6;
			ftrace_duration(dur_loc,
					fbuf->begin_time[fbuf->ret_idx],
					barrier_read_counter_timer());
		}
	}

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
