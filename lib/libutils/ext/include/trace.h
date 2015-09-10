/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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

#endif /* TRACE_H */
