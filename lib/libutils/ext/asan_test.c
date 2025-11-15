// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Linutronix GmbH
 */

#include <asan.h>
#include <asan_test.h>
#include <setjmp.h>
#include <malloc.h>
#include <config.h>
#include <util.h>
#include <trace.h>

#define ASAN_TEST_SUCCESS 1
#define ASAN_TEST_BUF_SIZE 15

static char asan_test_sgbuf[ASAN_TEST_BUF_SIZE];
char asan_test_gbuf[ASAN_TEST_BUF_SIZE];
static const char asan_test_sgbuf_ro[ASAN_TEST_BUF_SIZE + 1];

static jmp_buf asan_test_jmp;

static void asan_out_of_bounds_write(char *buf, size_t pos,
				     char value)
{
	buf[pos] = value;
}

static char asan_out_of_bounds_read(char *buf, size_t pos)
{
	return buf[pos];
}

static void *asan_out_of_bounds_memcpy(void *__restrict dst,
				       const void *__restrict src,
				       size_t size)
{
	return memcpy(dst, src, size);
}

static void *asan_out_of_bounds_memset(void *buf, int val, size_t size)
{
	return memset(buf, val, size);
}

static void asan_panic_test(void)
{
	longjmp(asan_test_jmp, ASAN_TEST_SUCCESS);
}

static void asan_test_cleanup(struct asan_test_ctx *ctx)
{
	unsigned int i = 0;

	free(ctx->pmalloc1);

	for (; i < ARRAY_SIZE(ctx->pmalloc2); i++)
		free(ctx->pmalloc2[i]);
}

void asan_test_stack(struct asan_test_ctx *ctx)
{
	char buf[ASAN_TEST_BUF_SIZE] = {0};

	ctx->write_func(buf, ASAN_TEST_BUF_SIZE, ctx->write_value);
}

void asan_test_global_stat(struct asan_test_ctx *ctx)
{
	ctx->write_func(asan_test_sgbuf, ASAN_TEST_BUF_SIZE,
			ctx->write_value);
}

void asan_test_global_ro(struct asan_test_ctx *ctx)
{
	ctx->read_func((char *)asan_test_sgbuf_ro,
		       ASAN_TEST_BUF_SIZE + 1);
}

void asan_test_global(struct asan_test_ctx *ctx)
{
	ctx->write_func(asan_test_gbuf, ASAN_TEST_BUF_SIZE,
			ctx->write_value);
}

void asan_test_malloc(struct asan_test_ctx *ctx)
{
	ctx->pmalloc1 = malloc(ASAN_TEST_BUF_SIZE);

	if (ctx->pmalloc1)
		ctx->write_func(ctx->pmalloc1, ASAN_TEST_BUF_SIZE,
				ctx->write_value);
}

void asan_test_malloc2(struct asan_test_ctx *ctx)
{
	size_t aligned_size = ROUNDUP(ASAN_TEST_BUF_SIZE, 8);
	unsigned int i = 0;
	char *p = NULL;

	for (; i < ARRAY_SIZE(ctx->pmalloc2); i++) {
		ctx->pmalloc2[i] = malloc(aligned_size);
		if (!ctx->pmalloc2[i])
			return;
	}
	p = ctx->pmalloc2[1];
	ctx->write_func(p, aligned_size, ctx->write_value);
}

void asan_test_use_after_free(struct asan_test_ctx *ctx)
{
	char *a = malloc(ASAN_TEST_BUF_SIZE);

	if (a) {
		ctx->free_func(a);
		ctx->write_func(a, 0, ctx->write_value);
	}
}

void asan_test_memcpy_dst(struct asan_test_ctx *ctx)
{
	static char b[ASAN_TEST_BUF_SIZE + 1];
	static char a[ASAN_TEST_BUF_SIZE];

	ctx->memcpy_func(a, b, sizeof(b));
}

void asan_test_memcpy_src(struct asan_test_ctx *ctx)
{
	static char a[ASAN_TEST_BUF_SIZE + 1];
	static char b[ASAN_TEST_BUF_SIZE];

	ctx->memcpy_func(a, b, sizeof(a));
}

void asan_test_memset(struct asan_test_ctx *ctx)
{
	static char b[ASAN_TEST_BUF_SIZE];

	ctx->memset_func(b, ctx->write_value, ASAN_TEST_BUF_SIZE + 1);
}

static void asan_test_free(void *ptr)
{
	free(ptr);
}

void asan_test_init(struct asan_test_ctx *ctx)
{
	ctx->write_value = 0xab;
	ctx->write_func = asan_out_of_bounds_write;
	ctx->read_func = asan_out_of_bounds_read;
	ctx->memcpy_func = asan_out_of_bounds_memcpy;
	ctx->memset_func = asan_out_of_bounds_memset;
	ctx->free_func = asan_test_free;

	asan_set_panic_cb(asan_panic_test);
}

void asan_test_deinit(struct asan_test_ctx *ctx)
{
	asan_test_cleanup(ctx);
	asan_set_panic_cb(asan_panic);
}

int asan_call_test(struct asan_test_ctx *ctx,
		   void (*test)(struct asan_test_ctx *ctx),
		   const char __unused *desc)
{
	int ret = 0;

	ret = setjmp(asan_test_jmp);
	if (ret == 0) {
		test(ctx);
		ret = -1;
	} else if (ret == ASAN_TEST_SUCCESS) {
		ret = 0;
	} else {
		asan_panic();
	}
	IMSG("  => [asan] test %s: %s", desc, !ret ? "ok" : "FAILED");

	return ret;
}
