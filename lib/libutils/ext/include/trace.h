/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef TRACE_H
#define TRACE_H

#include <stdbool.h>
#include <stddef.h>
#include <compiler.h>
#include <trace_levels.h>

#define MAX_PRINT_SIZE      256
#define MAX_FUNC_PRINT_SIZE 32

#ifndef TRACE_LEVEL
#define TRACE_LEVEL TRACE_MAX
#endif

/*
 * Symbols provided by the entity that uses this API.
 */
extern int trace_level;
extern const char trace_ext_prefix[];
void trace_ext_puts(const char *str);
int trace_ext_get_thread_id(void);
void trace_set_level(int level);
int trace_get_level(void);

/* Internal functions used by the macros below */
void trace_printf(const char *func, int line, int level, bool level_ok,
		  const char *fmt, ...) __printf(5, 6);

#define trace_printf_helper(level, level_ok, ...) \
	trace_printf(__func__, __LINE__, (level), (level_ok), \
		     __VA_ARGS__)

/* Formatted trace tagged with level independent */
#if (TRACE_LEVEL <= 0)
#define MSG(...)   (void)0
#else
#define MSG(...)   trace_printf_helper(0, false, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_ERROR level */
#if (TRACE_LEVEL < TRACE_ERROR)
#define EMSG(...)   (void)0
#else
#define EMSG(...)   trace_printf_helper(TRACE_ERROR, true, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_INFO level */
#if (TRACE_LEVEL < TRACE_INFO)
#define IMSG(...)   (void)0
#else
#define IMSG(...)   trace_printf_helper(TRACE_INFO, true, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_DEBUG level */
#if (TRACE_LEVEL < TRACE_DEBUG)
#define DMSG(...)   (void)0
#else
#define DMSG(...)   trace_printf_helper(TRACE_DEBUG, true, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_FLOW level */
#if (TRACE_LEVEL < TRACE_FLOW)
#define FMSG(...)   (void)0
#else
#define FMSG(...)   trace_printf_helper(TRACE_FLOW, true, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_FLOW level and prefix with '> ' */
#define INMSG(...)     FMSG("> " __VA_ARGS__)
/* Formatted trace tagged with TRACE_FLOW level and prefix with '< ' */
#define OUTMSG(...)    FMSG("< " __VA_ARGS__)
/* Formatted trace tagged with TRACE_FLOW level and prefix with '< ' and print
 * an error message if r != 0 */
#define OUTRMSG(r)			\
	do {				\
		OUTMSG("r=[%x]", r);	\
		return r;		\
	} while (0)

void dhex_dump(const char *function, int line, int level,
	       const void *buf, int len);
#if (TRACE_LEVEL < TRACE_DEBUG)
#define DHEXDUMP(buf, len) (void)0
#else
#define DHEXDUMP(buf, len) dhex_dump(__func__, __LINE__, TRACE_DEBUG, \
				     buf, len)
#endif


/* Trace api without trace formatting */

#define trace_printf_helper_raw(level, level_ok, ...) \
	trace_printf(NULL, 0, (level), (level_ok), __VA_ARGS__)

/* No formatted trace tagged with level independent */
#if (TRACE_LEVEL <= 0)
#define MSG_RAW(...)   (void)0
#else
#define MSG_RAW(...)   trace_printf_helper_raw(0, false, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_ERROR level */
#if (TRACE_LEVEL < TRACE_ERROR)
#define EMSG_RAW(...)   (void)0
#else
#define EMSG_RAW(...)   trace_printf_helper_raw(TRACE_ERROR, true, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_INFO level */
#if (TRACE_LEVEL < TRACE_INFO)
#define IMSG_RAW(...)   (void)0
#else
#define IMSG_RAW(...)   trace_printf_helper_raw(TRACE_INFO, true, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_DEBUG level */
#if (TRACE_LEVEL < TRACE_DEBUG)
#define DMSG_RAW(...)   (void)0
#else
#define DMSG_RAW(...)   trace_printf_helper_raw(TRACE_DEBUG, true, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_FLOW level */
#if (TRACE_LEVEL < TRACE_FLOW)
#define FMSG_RAW(...)   (void)0
#else
#define FMSG_RAW(...)   trace_printf_helper_raw(TRACE_FLOW, true, __VA_ARGS__)
#endif

#if (TRACE_LEVEL <= 0)
#define SMSG(...)   (void)0
#else
/*
 * Synchronised flushed trace, an Always message straight to HW trace IP.
 * Current only supported inside OP-TEE kernel, will be just like an EMSG()
 * in another context.
 */
#define SMSG(...)   \
	trace_printf(__func__, __LINE__, TRACE_ERROR, true, __VA_ARGS__)

#endif /* TRACE_LEVEL */

#if defined(__KERNEL__) && defined(CFG_UNWIND)
#include <kernel/unwind.h>
#define _PRINT_STACK
#endif

#if defined(_PRINT_STACK) && (TRACE_LEVEL >= TRACE_ERROR)
#define EPRINT_STACK() print_kernel_stack(TRACE_ERROR)
#else
#define EPRINT_STACK() (void)0
#endif

#if defined(_PRINT_STACK) && (TRACE_LEVEL >= TRACE_INFO)
#define IPRINT_STACK() print_kernel_stack(TRACE_INFO)
#else
#define IPRINT_STACK() (void)0
#endif

#if defined(_PRINT_STACK) && (TRACE_LEVEL >= TRACE_DEBUG)
#define DPRINT_STACK() print_kernel_stack(TRACE_DEBUG)
#else
#define DPRINT_STACK() (void)0
#endif

#if defined(_PRINT_STACK) && (TRACE_LEVEL >= TRACE_FLOW)
#define FPRINT_STACK() print_kernel_stack(TRACE_FLOW)
#else
#define FPRINT_STACK() (void)0
#endif

#if defined(__KERNEL__) && defined(CFG_UNWIND)
#undef _PRINT_STACK
#endif

#endif /* TRACE_H */
