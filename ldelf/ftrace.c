// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <assert.h>
#include <printk.h>
#include <string.h>
#include <sys/queue.h>
#include <types_ext.h>
#include <user_ta_header.h>
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
	size_t pad = 0;
	char *p = NULL;
	char magic[] = { 'F', 'T', 'R', 'A', 'C', 'E', 0x00, 0x01 };

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
	p = (char *)fbuf + fbuf->head_off;
	count = snprintk(p, MAX_HEADER_STRLEN,
			 "Function graph for TA: %pUl @ %lx\n",
			 (void *)&elf->uuid, elf->load_addr);
	assert(count < MAX_HEADER_STRLEN);
	p += count;

	fbuf->ret_func_ptr = finfo->ret_ptr.ptr64;
	fbuf->ret_idx = 0;
	fbuf->lr_idx = 0;
	fbuf->suspend_time = 0;
	fbuf->buf_off = fbuf->head_off + count;
	/* For proper alignment of uint64_t values in the ftrace buffer  */
	pad = 8 - (vaddr_t)p % 8;
	if (pad == 8)
		pad = 0;
	while (pad--) {
		*p++ = 0;
		fbuf->buf_off++;
		count++;
	}
	/* Delimiter for easier decoding */
	memcpy(p, magic, sizeof(magic));
	fbuf->buf_off += sizeof(magic);
	count += sizeof(magic);
	fbuf->curr_idx = 0;
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
		char *hstart = (char *)fbuf + fbuf->head_off;
		char *cstart = (char *)fbuf + fbuf->buf_off;
		char *ccurr = cstart + fbuf->curr_idx * sizeof(uint64_t);
		size_t csize = 0;
		size_t dump_size = 0;
		char *end = NULL;

		assert(elf && elf->is_main);

		if (fbuf->overflow)
			csize = fbuf->max_size;
		else
			csize = fbuf->curr_idx * sizeof(uint64_t);
		dump_size = fbuf->buf_off - fbuf->head_off + csize;
		end = hstart + dump_size;

		/* Header */
		copy_func(pctx, hstart, fbuf->buf_off - fbuf->head_off);
		if (fbuf->overflow) {
			/* From current index to end of circular buffer */
			copy_func(pctx, ccurr, end - ccurr);
		}
		/* From start of circular buffer to current index */
		copy_func(pctx, cstart, ccurr - cstart);
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
