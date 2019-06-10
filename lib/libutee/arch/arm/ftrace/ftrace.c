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

#include <setjmp.h>
#include <user_ta_header.h>
#include <utee_syscalls.h>
#include "ftrace.h"

static const char hex_str[] = "0123456789abcdef";

/*
 * This API shifts/moves ftrace buffer to create space for new dump
 * in case the buffer size falls short of actual dump.
 */
static void __noprof fbuf_shift(struct ftrace_buf *fbuf, size_t size)
{
	char *dst = (char *)fbuf + fbuf->buf_off;
	const char *src = (char *)fbuf + fbuf->buf_off + size;
	size_t n = 0;

	fbuf->curr_size -= size;

	for (n = 0; n < fbuf->curr_size; n++)
		dst[n] = src[n];
}

static size_t __noprof to_func_enter_fmt(char *buf, uint32_t ret_idx,
					 unsigned long pc)
{
	char *str = buf;
	uint32_t addr_size = 2 * sizeof(unsigned long);
	uint32_t i = 0;

	for (i = 0; i < ret_idx; i++)
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

	fbuf = &__ftrace_buf_start;

	if (!fbuf->buf_off || !fbuf->max_size)
		return;

	dump_size = fbuf->ret_idx + (2 * sizeof(unsigned long)) + 8;

	/*
	 * Check if we have enough space in ftrace buffer. If not then just
	 * remove oldest dump under the assumption that its the least
	 * interesting data.
	 */
	if ((fbuf->curr_size + dump_size) > fbuf->max_size)
		fbuf_shift(fbuf, dump_size);

	fbuf->curr_size += to_func_enter_fmt((char *)fbuf + fbuf->buf_off +
					     fbuf->curr_size, fbuf->ret_idx,
					     pc);

	if (fbuf->ret_idx < FTRACE_RETFUNC_DEPTH) {
		fbuf->ret_stack[fbuf->ret_idx] = *lr;
		fbuf->ret_idx++;
	} else {
		/*
		 * This scenario isn't expected as function call depth
		 * shouldn't be more than FTRACE_RETFUNC_DEPTH.
		 */
		utee_panic(0);
	}

	*lr = (unsigned long)&__ftrace_return;
}

unsigned long __noprof ftrace_return(void)
{
	struct ftrace_buf *fbuf = NULL;
	size_t dump_size = 0;
	char *curr_buf = NULL;
	uint32_t i = 0;

	fbuf = &__ftrace_buf_start;

	/* Check for valid return index */
	if (fbuf->ret_idx && (fbuf->ret_idx <= FTRACE_RETFUNC_DEPTH))
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
	} else {
		dump_size = fbuf->ret_idx + 3;
		if ((fbuf->curr_size + dump_size) > fbuf->max_size)
			fbuf_shift(fbuf, dump_size);

		curr_buf = (char *)fbuf + fbuf->buf_off + fbuf->curr_size;

		for (i = 0; i < fbuf->ret_idx; i++)
			*curr_buf++ = ' ';

		*curr_buf++ = '}';
		*curr_buf++ = '\n';
		*curr_buf = '\0';

		fbuf->curr_size += dump_size - 1;
	}

	return fbuf->ret_stack[fbuf->ret_idx];
}

void __noprof ftrace_longjmp(unsigned int *ret_idx)
{
	while (__ftrace_buf_start.ret_idx > *ret_idx)
		ftrace_return();
}

void __noprof ftrace_setjmp(unsigned int *ret_idx)
{
	*ret_idx = __ftrace_buf_start.ret_idx;
}
