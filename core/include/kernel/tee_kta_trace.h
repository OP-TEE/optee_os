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
#ifndef TEE_KTA_TRACE_H
#define TEE_KTA_TRACE_H

#include <tee_trace.h>

/*****************************************************************************/

extern int _ta_trace_level;

/*****************************************************************************/

#ifndef STR_TRACE_KERNEL_TA
#define STR_TRACE_KERNEL_TA "KERNEL-TA"
#endif

/*****************************************************************************/
/* Trace api with trace formatting */

/* Filtering and call backend method */
#define tadprintf(level, ...)						\
	do {								\
		if ((level) <= _ta_trace_level) {			\
			_dprintf(__func__,  __LINE__, level,		\
				 STR_TRACE_KERNEL_TA, __VA_ARGS__);	\
	    }								\
	} while (0)

/* Formatted trace tagged with TRACE_ALWAYS level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ALWAYS)
#define ATAMSG(...)   (void)0
#else
#define ATAMSG(...)   \
_dprintf(__func__, __LINE__, TRACE_ALWAYS, STR_TRACE_KERNEL_TA, __VA_ARGS__);
#endif

/* Formatted trace tagged with TRACE_ERROR level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ERROR)
#define ETAMSG(...)   (void)0
#else
#define ETAMSG(...)   tadprintf(TRACE_ERROR, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_INFO level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_INFO)
#define ITAMSG(...)   (void)0
#else
#define ITAMSG(...)   tadprintf(TRACE_INFO, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_DEBUG level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_DEBUG)
#define DTAMSG(...)   (void)0
#else
#define DTAMSG(...)   tadprintf(TRACE_DEBUG, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_FLOW level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_FLOW)
#define FTAMSG(...)   (void)0
#else
#define FTAMSG(...)   tadprintf(TRACE_FLOW, __VA_ARGS__)
#endif

/* Formatted trace tagged with TRACE_FLOW level and prefix with '> ' */
#define TAINMSG(...)     FTAMSG("> " __VA_ARGS__)
/* Formatted trace tagged with TRACE_FLOW level and prefix with '< ' */
#define TAOUTMSG(...)    FTAMSG("< " __VA_ARGS__)
/* Formatted trace tagged with TRACE_FLOW level and prefix with '< ' and print
 * an error message if r != 0 */
#define TAOUTRMSG(r)				\
	do {					\
		OUTMSG("r=[%lx]", r);		\
		return r;			\
	} while (0)

/*****************************************************************************/
/* Trace api without trace formatting */

/* Filtering and call backend method */
#define tadprintf_raw(level, ...)					\
	do {								\
		if ((level) <= _ta_trace_level) {			\
			_dprintf(NULL, 0, level, STR_TRACE_KERNEL_TA,	\
				 __VA_ARGS__);				\
		}							\
	} while (0)

/* No formatted trace tagged with TRACE_ALWAYS level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ALWAYS)
#define ATAMSG_RAW(...)   (void)0
#else
#define ATAMSG_RAW(...)   \
	_dprintf(NULL, 0, TRACE_ALWAYS, STR_TRACE_KERNEL_TA, __VA_ARGS__);
#endif

/* No formatted trace tagged with TRACE_ERROR level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ERROR)
#define ETAMSG_RAW(...)   (void)0
#else
#define ETAMSG_RAW(...)   tadprintf_raw(TRACE_ERROR, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_INFO level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_INFO)
#define ITAMSG_RAW(...)   (void)0
#else
#define ITAMSG_RAW(...)   tadprintf_raw(TRACE_INFO, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_DEBUG level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_DEBUG)
#define DTAMSG_RAW(...)   (void)0
#else
#define DTAMSG_RAW(...)   tadprintf_raw(TRACE_DEBUG, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_FLOW level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_FLOW)
#define FTAMSG_RAW(...)   (void)0
#else
#define FTAMSG_RAW(...)   tadprintf_raw(TRACE_FLOW, __VA_ARGS__)
#endif

/*****************************************************************************/

/* Accessors */
#if (CFG_TEE_TA_LOG_LEVEL == 0)
static inline void set_ta_trace_level(int level) { }
static inline int get_ta_trace_level(void) { return 0; }
static inline void ta_trace_test(void) { }
#else
void set_ta_trace_level(int level);
int get_ta_trace_level(void);
void ta_trace_test(void);
#endif

#endif /* TEE_KTA_TRACE_H */
