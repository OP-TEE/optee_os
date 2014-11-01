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
#ifndef TEE_CORE_TRACE_H
#define TEE_CORE_TRACE_H

#include <tee_trace.h>
#include <compiler.h>

/*****************************************************************************/

#if (CFG_TEE_CORE_LOG_LEVEL > 0)
extern int _trace_level;
#endif

/*****************************************************************************/

#ifndef STR_TRACE_CORE
#define STR_TRACE_CORE "TEE-CORE"
#endif

/*****************************************************************************/
/* Trace api with trace formatting */

/* Filtering and call backend method */
#define dprintf_level(level, ...)					\
	do {								\
	    if ((level) <= _trace_level) {				\
		_dprintf(__func__, __LINE__,				\
			 level, STR_TRACE_CORE, __VA_ARGS__);		\
	    }								\
	} while (0)

/* Formatted trace tagged with TRACE_ALWAYS level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_ALWAYS)
#define AMSG(...)   (void)0
#else
#define AMSG(...)   \
	_dprintf(__func__, __LINE__, TRACE_ALWAYS, STR_TRACE_CORE, __VA_ARGS__);
#endif

/* Formatted trace tagged with TRACE_ERROR level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_ERROR)
#define EMSG(...)   (void)0
#else
#define EMSG(...)   dprintf_level(TRACE_ERROR, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_INFO level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_INFO)
#define IMSG(...)   (void)0
#else
#define IMSG(...)   dprintf_level(TRACE_INFO, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_DEBUG level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_DEBUG)
#define DMSG(...)   (void)0
#else
#define DMSG(...)   dprintf_level(TRACE_DEBUG, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_FLOW level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_FLOW)
#define FMSG(...)   (void)0
#else
#define FMSG(...)   dprintf_level(TRACE_FLOW, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_FLOW level and prefix with '> ' */
#define INMSG(...)     FMSG("> " __VA_ARGS__)
/* Formatted trace tagged with TRACE_FLOW level and prefix with '< ' */
#define OUTMSG(...)    FMSG("< " __VA_ARGS__)
/* Formatted trace tagged with TRACE_FLOW level and prefix with '< ' and print
 * an error message if r != 0 */
#define OUTRMSG(r)                  \
	do {                        \
	    OUTMSG("r=[%x]", r);    \
	    return r;               \
	} while (0)

#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_DEBUG)
#define DHEXDUMP(buf, len) (void)0
#else
#define DHEXDUMP(buf, len) dhex_dump(__func__, __LINE__, TRACE_DEBUG, \
				     STR_TRACE_CORE, buf, len)
void dhex_dump(const char *function, int line, int level, const char *prefix,
	       const void *buf, int len);
#endif

/*****************************************************************************/
/* Trace api without trace formatting */

#define dprintf_raw(level, ...)						\
	do {								\
	    if ((level) <= _trace_level) {				\
		_dprintf(NULL, 0, level, STR_TRACE_CORE, __VA_ARGS__);	\
	    }								\
	} while (0)

/* No formatted trace tagged with TRACE_ALWAYS level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_ALWAYS)
#define AMSG_RAW(...)   (void)0
#else
#define AMSG_RAW(...)   \
	_dprintf(NULL, 0, TRACE_ALWAYS, STR_TRACE_CORE, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_ERROR level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_ERROR)
#define EMSG_RAW(...)   (void)0
#else
#define EMSG_RAW(...)   dprintf_raw(TRACE_ERROR, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_INFO level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_INFO)
#define IMSG_RAW(...)   (void)0
#else
#define IMSG_RAW(...)   dprintf_raw(TRACE_INFO, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_DEBUG level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_DEBUG)
#define DMSG_RAW(...)   (void)0
#else
#define DMSG_RAW(...)   dprintf_raw(TRACE_DEBUG, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_FLOW level */
#if (CFG_TEE_CORE_LOG_LEVEL < TRACE_FLOW)
#define FMSG_RAW(...)   (void)0
#else
#define FMSG_RAW(...)   dprintf_raw(TRACE_FLOW, __VA_ARGS__)
#endif

#if (CFG_TEE_CORE_LOG_LEVEL == 0)
#define SMSG(...)   (void)0
static inline void set_trace_level(int level __unused) { }
static inline int get_trace_level(void) { return 0; }
static inline void core_trace_test(void) { }
#else
/*
 * Synchronised flushed trace, an Always message straight to HW trace IP.
 * Current only supported inside teecore (not in kernel or user TA).
 */
#define SMSG(...)   _dprintf_hwsync(__func__, __LINE__, __VA_ARGS__)
int _dprintf_hwsync(const char *function, int line, const char *fmt,
		    ...) __PRINTFLIKE(3, 4);

/* Accessors */
void set_trace_level(int level);
int get_trace_level(void);
void core_trace_test(void);

#if (CFG_TEE_CORE_LOG_LEVEL == TRACE_FLOW)
void _trace_syscall(int num);
#endif

#endif /* CFG_TEE_CORE_LOG_LEVEL */

#endif /* TEE_CORE_TRACE_H */
