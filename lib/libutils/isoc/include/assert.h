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

/* This macro is deprecated, please use static_assert instead */
#define COMPILE_TIME_ASSERT(x) \
	do { \
		switch (0) { case 0: case ((x) ? 1: 0): default : break; } \
	} while (0)

#endif

#if !defined(__cplusplus) || (__cplusplus < 201103L)
#if defined(__HAVE_SINGLE_ARGUMENT_STATIC_ASSERT)
#define static_assert _Static_assert
#else
/*
 * In gcc prior to 9.1 _Static_assert requires two arguments. To allow
 * passing a single argument to static_assert() add a workaround with
 * macros.
 */
#define ___args_count(_0, _1, x, ...) x
#define __args_count(...) ___args_count(__VA_ARGS__, 2, 1, 0)

#define __static_assert_1(expr)		_Static_assert(expr, "")
#define __static_assert_2(expr, msg)	_Static_assert(expr, msg)
#define ___static_assert(count, ...)	__static_assert_ ## count(__VA_ARGS__)
#define __static_assert(count, ...)	___static_assert(count, __VA_ARGS__)

#define static_assert(...) \
	__static_assert(__args_count(__VA_ARGS__), __VA_ARGS__)
#endif
#endif
