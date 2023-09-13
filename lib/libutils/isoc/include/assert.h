/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __ASSERT_H
#define __ASSERT_H

#include <compiler.h>
#include <trace.h>

void __noreturn _assert_break(void);
void _assert_log(const char *expr, const char *file, const int line,
			const char *func);

static inline void __noreturn _assert_trap(const char *expr_str,
					   const char *file, const int line,
					   const char *func)
{
	_assert_log(expr_str, file, line, func);
	_assert_break();
}

static inline void _runtime_assert_trap(const char *expr_str, const char *file,
					const int line, const char *func)
{
	volatile bool do_break = true;

	_assert_log(expr_str, file, line, func);
	if (do_break)
		_assert_break();
}

/*
 * runtime_assert() behaves as assert() except that it doesn't tell the
 * compiler it will never return. This can be used to avoid the warning:
 * error: function might be candidate for attribute ‘noreturn’
 */
#ifdef NDEBUG
#define assert(expr)	((void)0)
#define runtime_assert(expr)	((void)0)
#else
#define assert(expr)	\
	((expr) ? (void)0 : _assert_trap(#expr, __FILE__, __LINE__, __func__))
#define runtime_assert(expr)	\
	((expr) ? (void)0 : \
		_runtime_assert_trap(#expr, __FILE__, __LINE__, __func__))
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
#endif /* __ASSERT_H */
