/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef KERNEL_PANIC_H
#define KERNEL_PANIC_H

#include <compiler.h>

/* debug disabled => __FILE__, ... and panic message are not built. */
#if defined(CFG_TEE_CORE_DEBUG)
#define __panic(str)	__do_panic(__FILE__, __LINE__, __func__, str)
#else
#define __panic(str)	__do_panic((void *)0, 0, (void *)0, str)
#endif

void __do_panic(const char *file, const int line, const char *func,
		const char *msg) __noreturn;

/*
 * Suppress GCC warning on expansion of the panic() macro with no argument:
 *  'ISO C99 requires at least one argument for the "..." in a variadic macro'
 * Occurs when '-pedantic' is combined with '-std=gnu99'.
 * Suppression applies only to this file and the expansion of macros defined in
 * this file.
 */
#pragma GCC system_header

/* panic() can get a string or no argument */
#define _panic0()	__panic((void *)0)
#define _panic1(s)	__panic(s)
#define _panic_fn(a, b, name, ...) name
#define panic(...) _panic_fn("", ##__VA_ARGS__, _panic1, _panic0)(__VA_ARGS__)

/*
 * Weak function used in __do_panic() to put the current CPU on hold.
 * If no arch-specific override is provided, defaults to a busy loop.
 */
void cpu_idle(void);

#endif /*KERNEL_PANIC_H*/
