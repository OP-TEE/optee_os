// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2022-2023, Arm Limited
 */

#include <assert.h>
#include <ldelf.h>
#include <malloc.h>
#include <printk.h>
#include <string.h>
#include <sys/queue.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#include "dl.h"
#include "ftrace.h"
#include "sys.h"
#include "ta_elf.h"

static size_t mpool_size = 4 * SMALL_PAGE_SIZE;
static vaddr_t mpool_base;

static void __printf(2, 0) print_to_console(void *pctx __unused,
					    const char *fmt, va_list ap)
{
	trace_vprintf(NULL, 0, TRACE_ERROR, true, fmt, ap);
}

static void __noreturn __maybe_unused dump_ta_state(struct dump_entry_arg *arg)
{
	struct ta_elf *elf = TAILQ_FIRST(&main_elf_queue);

	assert(elf && elf->is_main);
	EMSG_RAW("Status of TA %pUl", (void *)&elf->uuid);
#if defined(ARM32) || defined(ARM64)
	EMSG_RAW(" arch: %s", elf->is_32bit ? "arm" : "aarch64");
#elif defined(RV32) || defined(RV64)
	EMSG_RAW(" arch: %s", elf->is_32bit ? "riscv32" : "riscv64");
#endif

	ta_elf_print_mappings(NULL, print_to_console, &main_elf_queue,
			      arg->num_maps, arg->maps, mpool_base);

#if defined(ARM32) || defined(ARM64)
	if (arg->is_32bit)
		ta_elf_stack_trace_a32(arg->arm32.regs);
	else
		ta_elf_stack_trace_a64(arg->arm64.fp, arg->arm64.sp,
				       arg->arm64.pc);
#elif defined(RV32) || defined(RV64)
	ta_elf_stack_trace_riscv(arg->rv.fp, arg->rv.pc);
#endif

	sys_return_cleanup();
}

#ifdef CFG_FTRACE_SUPPORT
struct print_buf_ctx {
	char *buf;
	size_t blen;
	size_t ret;
};

static void __printf(2, 0) print_to_pbuf(void *pctx, const char *fmt,
					 va_list ap)
{
	struct print_buf_ctx *pbuf = pctx;
	char *buf = NULL;
	size_t blen = 0;
	int ret = 0;

	if (pbuf->buf && pbuf->blen > pbuf->ret) {
		buf = pbuf->buf + pbuf->ret;
		blen = pbuf->blen - pbuf->ret;
	}

	ret = vsnprintk(buf, blen, fmt, ap);
	assert(ret >= 0);

	pbuf->ret += ret;
}

static void copy_to_pbuf(void *pctx, void *b, size_t bl)
{
	struct print_buf_ctx *pbuf = pctx;
	char *buf = NULL;
	size_t blen = 0;

	if (pbuf->buf && pbuf->blen > pbuf->ret) {
		buf = pbuf->buf + pbuf->ret;
		blen = pbuf->blen - pbuf->ret;
		memcpy(buf, b, MIN(blen, bl));
	}

	pbuf->ret += bl;

}

static void __noreturn ftrace_dump(void *buf, size_t *blen)
{
	struct print_buf_ctx pbuf = { .buf = buf, .blen = *blen };

	ta_elf_print_mappings(&pbuf, print_to_pbuf, &main_elf_queue,
			      0, NULL, mpool_base);
	ftrace_copy_buf(&pbuf, copy_to_pbuf);
	*blen = pbuf.ret;
	sys_return_cleanup();
}
#endif

static void __noreturn dl_entry(struct dl_entry_arg *arg)
{
	switch (arg->cmd) {
	case LDELF_DL_ENTRY_DLOPEN:
		arg->ret = dlopen_entry(arg);
		break;
	case LDELF_DL_ENTRY_DLSYM:
		arg->ret = dlsym_entry(arg);
		break;
	default:
		arg->ret = TEE_ERROR_NOT_SUPPORTED;
	}

	sys_return_cleanup();
}

/*
 * ldelf()- Loads ELF into memory
 * @arg:	Argument passing to/from TEE Core
 *
 * Only called from assembly
 */
void __noreturn ldelf(struct ldelf_arg *arg);
void ldelf(struct ldelf_arg *arg)
{
	TEE_Result res = TEE_SUCCESS;
	struct ta_elf *elf = NULL;

	DMSG("Loading TS %pUl", (void *)&arg->uuid);
	res = sys_map_zi(mpool_size, 0, &mpool_base, 0, 0);
	if (res) {
		EMSG("sys_map_zi(%zu): result %"PRIx32, mpool_size, res);
		panic();
	}
	malloc_add_pool((void *)mpool_base, mpool_size);

	/* Load the main binary and get a list of dependencies, if any. */
	ta_elf_load_main(&arg->uuid, &arg->is_32bit, &arg->stack_ptr,
			 &arg->flags);

	/*
	 * Load binaries, ta_elf_load() may add external libraries to the
	 * list, so the loop will end when all the dependencies are
	 * satisfied.
	 */
	TAILQ_FOREACH(elf, &main_elf_queue, link)
		ta_elf_load_dependency(elf, arg->is_32bit);

	TAILQ_FOREACH(elf, &main_elf_queue, link) {
		ta_elf_relocate(elf);
		ta_elf_finalize_mappings(elf);
	}

	ta_elf_finalize_load_main(&arg->entry_func, &arg->load_addr);

	arg->ftrace_entry = 0;
#ifdef CFG_FTRACE_SUPPORT
	if (ftrace_init(&arg->fbuf))
		arg->ftrace_entry = (vaddr_t)(void *)ftrace_dump;
#endif

	TAILQ_FOREACH(elf, &main_elf_queue, link)
		DMSG("ELF (%pUl) at %#"PRIxVA,
		     (void *)&elf->uuid, elf->load_addr);

#if TRACE_LEVEL >= TRACE_ERROR
	arg->dump_entry = (vaddr_t)(void *)dump_ta_state;
#else
	arg->dump_entry = 0;
#endif
	arg->dl_entry = (vaddr_t)(void *)dl_entry;

	sys_return_cleanup();
}
