// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <assert.h>
#include <printk.h>
#include <sys/queue.h>
#include <types_ext.h>
#include <util.h>

#include "ftrace.h"
#include "ta_elf.h"

#define MIN_FTRACE_BUF_SIZE	1024
#define MAX_HEADER_STRLEN	128

static struct ftrace_buf *fbuf;

bool ftrace_init(struct ftrace_buf **fbuf_ptr)
{
	struct __ftrace_info *finfo = NULL;
	struct ta_elf *elf = TAILQ_FIRST(&main_elf_queue);
	TEE_Result res = TEE_SUCCESS;
	vaddr_t val = 0;
	int count = 0;
	size_t fbuf_size = 0;

	res = ta_elf_resolve_sym("__ftrace_info", &val, NULL, NULL);
	if (res)
		return false;

	finfo = (struct __ftrace_info *)val;

	assert(elf && elf->is_main);

	if (SUB_OVERFLOW(finfo->buf_end.ptr64, finfo->buf_start.ptr64,
			 &fbuf_size))
		return false;

	if (fbuf_size < MIN_FTRACE_BUF_SIZE) {
		DMSG("ftrace buffer too small");
		return false;
	}

	fbuf = (struct ftrace_buf *)(vaddr_t)finfo->buf_start.ptr64;
	fbuf->head_off = sizeof(struct ftrace_buf);
	count = snprintk((char *)fbuf + fbuf->head_off, MAX_HEADER_STRLEN,
			 "Function graph for TA: %pUl @ %lx\n",
			 (void *)&elf->uuid, elf->load_addr);
	assert(count < MAX_HEADER_STRLEN);

	fbuf->ret_func_ptr = finfo->ret_ptr.ptr64;
	fbuf->ret_idx = 0;
	fbuf->lr_idx = 0;
	fbuf->suspend_time = 0;
	fbuf->buf_off = fbuf->head_off + count;
	fbuf->curr_size = 0;
	fbuf->max_size = fbuf_size - sizeof(struct ftrace_buf) - count;
	fbuf->syscall_trace_enabled = false;
	fbuf->syscall_trace_suspended = false;

	*fbuf_ptr = fbuf;

	return true;
}

void ftrace_copy_buf(void *pctx, void (*copy_func)(void *pctx, void *b,
						   size_t bl))
{
	if (fbuf) {
		struct ta_elf *elf = TAILQ_FIRST(&main_elf_queue);
		size_t dump_size = fbuf->buf_off - fbuf->head_off +
				   fbuf->curr_size;

		assert(elf && elf->is_main);
		copy_func(pctx, (char *)fbuf + fbuf->head_off, dump_size);
	}
}

void ftrace_map_lr(uint64_t *lr)
{
	if (fbuf) {
		if (*lr == fbuf->ret_func_ptr &&
		    fbuf->lr_idx < fbuf->ret_idx) {
			fbuf->lr_idx++;
			*lr = fbuf->ret_stack[fbuf->ret_idx - fbuf->lr_idx];
		}
	}
}
