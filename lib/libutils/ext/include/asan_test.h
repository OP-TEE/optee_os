/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Linutronix GmbH
 */
#ifndef __ASAN_TEST_H
#define __ASAN_TEST_H

#include <compiler.h>
#include <stddef.h>

/*
 * Context used by ASan runtime tests.
 */
struct asan_test_ctx {
	char *pmalloc1;
	char *pmalloc2[3];
	char write_value;
	void (*write_func)(char *buf, size_t pos, char value);
	char (*read_func)(char *buf, size_t pos);
	void *(*memcpy_func)(void *__restrict dst,
			     const void *__restrict src, size_t size);
	void *(*memset_func)(void *buf, int val, size_t size);
	void (*free_func)(void *ptr);
};


/*
 * Initialize ASan test context.
 * Allocations and function pointers are set up for subsequent tests.
 */
void asan_test_init(struct asan_test_ctx *ctx);

/*
 * Release any resources owned by the context.
 */
void asan_test_deinit(struct asan_test_ctx *ctx);

/*
 * Helper to run a single ASan test.
 *
 * Returns 0 on success, or a negative error code on internal failure.
 */
int asan_call_test(struct asan_test_ctx *ctx,
		   void (*test)(struct asan_test_ctx *ctx),
		   const char __unused *desc);

/* Individual ASan test cases */
void asan_test_stack(struct asan_test_ctx *ctx);
void asan_test_global_stat(struct asan_test_ctx *ctx);
void asan_test_global_ro(struct asan_test_ctx *ctx);
void asan_test_global(struct asan_test_ctx *ctx);
void asan_test_malloc(struct asan_test_ctx *ctx);
void asan_test_malloc2(struct asan_test_ctx *ctx);
void asan_test_use_after_free(struct asan_test_ctx *ctx);
void asan_test_memcpy_dst(struct asan_test_ctx *ctx);
void asan_test_memcpy_src(struct asan_test_ctx *ctx);
void asan_test_memset(struct asan_test_ctx *ctx);

#endif /* __ASAN_TEST_H */
