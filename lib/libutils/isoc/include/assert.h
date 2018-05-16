/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef ASSERT_H
#define ASSERT_H

#include <compiler.h>
#include <trace.h>

void __noreturn _assert_break(void);
void _assert_log(const char *expr, const char *file, const int line,
			const char *func);

/* assert() specs: generates a log but does not panic if NDEBUG is defined */
#ifdef NDEBUG
#define assert(expr)	do { } while (0)
#else
#define assert(expr) \
	do { \
		if (!(expr)) { \
			_assert_log(#expr, __FILE__, __LINE__, __func__); \
			_assert_break(); \
		} \
	} while (0)
#endif

#define COMPILE_TIME_ASSERT(x) \
	do { \
		switch (0) { case 0: case ((x) ? 1: 0): default : break; } \
	} while (0)

#endif
