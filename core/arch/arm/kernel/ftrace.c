// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Linaro Limited
 */

#include <assert.h>
#include <kernel/ftrace.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <kernel/tee_ta_manager.h>
#include <mm/mobj.h>
#include <mm/tee_mmu.h>
#include <optee_rpc_cmd.h>
#include <printk.h>
#include <string.h>
#include <trace.h>
#include "elf_load_dyn.h"

#define MIN_FTRACE_BUF_SIZE	1024
#define MAX_HEADER_STRLEN	128

void ta_fbuf_init(vaddr_t load_addr, struct tee_ta_session *s,
		  struct elf_load_state *state)
{
	struct __ftrace_info *finfo = NULL;
	struct ftrace_buf *fbuf = NULL;
	struct user_ta_ctx *utc = to_user_ta_ctx(s->ctx);
	size_t fbuf_size = 0;
	uintptr_t val = 0;
	int count = 0;
	TEE_Result res = TEE_SUCCESS;

	if (state->is_32bit) {
		DMSG("Current ftrace doesn't support 32 bit TAs");
		return;
	}

	res = elf_resolve_symbol(state, "__ftrace_info", &val);
	if (res != TEE_SUCCESS || !val) {
		DMSG("ftrace info not found");
		return;
	}

	finfo = (struct __ftrace_info *)(val + load_addr);

	if (!tee_mmu_is_vbuf_inside_ta_private(utc, finfo, sizeof(*finfo))) {
		EMSG("Incorrect struct __ftrace_info addr");
		return;
	}

	if (finfo->buf_end > finfo->buf_start)
		fbuf_size = finfo->buf_end - finfo->buf_start;

	if (!tee_mmu_is_vbuf_inside_ta_private(utc, (void *)finfo->buf_start,
					       fbuf_size)) {
		EMSG("Incorrect struct ftrace_buf addr");
		return;
	}

	if (fbuf_size >= MIN_FTRACE_BUF_SIZE) {
		fbuf = (struct ftrace_buf *)finfo->buf_start;
		fbuf->head_off = sizeof(struct ftrace_buf);
		count = snprintk((char *)fbuf + fbuf->head_off,
				 MAX_HEADER_STRLEN,
				 "Function graph for TA: %pUl @ %lx\n",
				 (void *)&s->ctx->uuid, load_addr);
		assert(count < MAX_HEADER_STRLEN);

		fbuf->ret_func_ptr = finfo->ret_ptr;
		fbuf->ret_idx = 0;
		fbuf->lr_idx = 0;
		fbuf->buf_off = fbuf->head_off + count;
		fbuf->curr_size = 0;
		fbuf->max_size = fbuf_size - sizeof(struct ftrace_buf) - count;

		s->fbuf = fbuf;
	} else {
		DMSG("ftrace buffer too small");

		s->fbuf = NULL;
	}
}

void ta_fbuf_dump(struct tee_ta_session *s)
{
	struct ftrace_buf *fbuf = NULL;
	struct mobj *mobj = NULL;
	char *va = NULL;
	uint32_t ret = 0;
	uint32_t dump_size = 0;
	struct thread_param params[3] = { };

	if (!s->fbuf)
		return;

	fbuf = s->fbuf;

	if (!fbuf->curr_size)
		DMSG("Ftrace buffer empty (no TA file compiled with -pg?)");

	dump_size = fbuf->buf_off - fbuf->head_off + fbuf->curr_size;

	mobj = thread_rpc_alloc_payload(sizeof(TEE_UUID) + dump_size);
	if (!mobj) {
		EMSG("Ftrace thread_rpc_alloc_payload failed");
		return;
	}

	va = mobj_get_va(mobj, 0);
	if (!va)
		goto exit;

	memcpy(va, &s->ctx->uuid, sizeof(TEE_UUID));
	memcpy(va + sizeof(TEE_UUID), (char *)fbuf + fbuf->head_off, dump_size);

	params[0] = THREAD_PARAM_VALUE(INOUT, 0, 0, 0);
	params[1] = THREAD_PARAM_MEMREF(IN, mobj, 0, sizeof(TEE_UUID));
	params[2] = THREAD_PARAM_MEMREF(IN, mobj, sizeof(TEE_UUID), dump_size);

	ret = thread_rpc_cmd(OPTEE_RPC_CMD_FTRACE, 3, params);
	if (ret)
		EMSG("Ftrace thread_rpc_cmd ret: %08x", ret);

exit:
	thread_rpc_free_payload(mobj);
}

void ftrace_ta_map_lr(uint64_t *lr)
{
	struct ftrace_buf *fbuf = NULL;
	struct tee_ta_session *s = NULL;

	if (tee_ta_get_current_session(&s) != TEE_SUCCESS)
		panic();

	if (!s->fbuf)
		return;

	fbuf = s->fbuf;

	/*
	 * Function tracer inserts return hook (addr: fbuf->ret_func_ptr)
	 * via modifying lr values in the stack frames. And during aborts,
	 * stack trace picks these modified lr values which needs to be
	 * replaced with original lr value. So here we use the ftrace return
	 * stack to retrieve original lr value but we need to first check if
	 * it has actually been modified or not in case TA is profiled
	 * partially.
	 */
	if ((*lr == fbuf->ret_func_ptr) && (fbuf->lr_idx < fbuf->ret_idx)) {
		fbuf->lr_idx++;
		*lr = fbuf->ret_stack[fbuf->ret_idx - fbuf->lr_idx];
	}
}
