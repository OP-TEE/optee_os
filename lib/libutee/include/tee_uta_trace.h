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
#ifndef TEE_UTA_TRACE_H
#define TEE_UTA_TRACE_H

#include <tee_trace.h>
#include <user_ta_header.h>

/*****************************************************************************/

#ifndef STR_TRACE_USER_TA
#define STR_TRACE_USER_TA "USER-TA"
#endif

#if (CFG_TEE_TA_LOG_LEVEL > 0)
int _dprintf_uta(const char *function, int line, int level, const char *prefix,
		 const char *fmt, ...) __PRINTFLIKE(5, 6);
#endif

/*****************************************************************************/
/* Trace api with trace formatting */

/* Filtering and call backend method.
 * Retrieve the ta level strored at kernel side by a sys call */
#define dprintf_level(level, ...)                                            \
do {                                                                         \
    if ((level) <= tahead_get_trace_level()) {                               \
        _dprintf_uta(__func__, __LINE__, level, STR_TRACE_USER_TA, __VA_ARGS__); \
    }                                                                        \
} while (0)

/* Formmated trace tagged with TRACE_ALWAYS level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ALWAYS)
#define AMSG(...)   (void)0
#else
#define AMSG(...)   _dprintf_uta(__func__, __LINE__, TRACE_ALWAYS, STR_TRACE_USER_TA, __VA_ARGS__);
#endif

/* Formmated trace tagged with TRACE_ERROR level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ERROR)
#define EMSG(...)   (void)0
#else
#define EMSG(...)   dprintf_level(TRACE_ERROR, __VA_ARGS__)
#endif

/* Formmated trace tagged with TRACE_INFO level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_INFO)
#define IMSG(...)   (void)0
#else
#define IMSG(...)   dprintf_level(TRACE_INFO, __VA_ARGS__)
#endif

/* Formmated trace tagged with TRACE_DEBUG level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_INFO)
#define DMSG(...)   (void)0
#else
#define DMSG(...)   dprintf_level(TRACE_DEBUG, __VA_ARGS__)
#endif

/* Formmated trace tagged with TRACE_FLOW level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_FLOW)
#define FMSG(...)   (void)0
#else
#define FMSG(...)   dprintf_level(TRACE_FLOW, __VA_ARGS__)
#endif

/* Formmated trace tagged with TRACE_FLOW level and prefix with '> ' */
#define INMSG(...)     FMSG("> " __VA_ARGS__)
/* Formmated trace tagged with TRACE_FLOW level and prefix with '< ' */
#define OUTMSG(...)    FMSG("< " __VA_ARGS__)
/* Formmated trace tagged with TRACE_FLOW level and prefix with '< ' and print an
 * error message if r != 0 */
#define OUTRMSG(r)                              \
do {                                            \
    OUTMSG("r=[%lx]", r);                          \
    return r;                                   \
} while (0);

/*****************************************************************************/
/* Trace api without trace formatting */

/* Filtering and call backend method.
 * Retrieve the ta level strored at kernel side by a sys call */
#define dprintf_raw(level, ...)                                             \
do {                                                                        \
    if ((level) <= tahead_get_trace_level()) {                   \
        _dprintf_uta(NULL, 0, level, STR_TRACE_USER_TA, __VA_ARGS__);           \
    }                                                                       \
} while (0)

/* No formatted trace tagged with TRACE_ALWAYS level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ALWAYS)
#define AMSG_RAW(...)   (void)0
#else
#define AMSG_RAW(...)   _dprintf_uta(NULL, 0, TRACE_ALWAYS, STR_TRACE_USER_TA, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_ERROR level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_ERROR)
#define EMSG_RAW(...)   (void)0
#else
#define EMSG_RAW(...)   dprintf_raw(TRACE_ERROR, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_INFO level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_INFO)
#define IMSG_RAW(...)   (void)0
#else
#define IMSG_RAW(...)   dprintf_raw(TRACE_INFO, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_DEBUG level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_DEBUG)
#define DMSG_RAW(...)   (void)0
#else
#define DMSG_RAW(...)   dprintf_raw(TRACE_DEBUG, __VA_ARGS__)
#endif

/* No formatted trace tagged with TRACE_FLOW level */
#if (CFG_TEE_TA_LOG_LEVEL < TRACE_FLOW)
#define FMSG(...)   (void)0
#else
#define FMSG_RAW(...)   dprintf_raw(TRACE_FLOW, __VA_ARGS__)
#endif

/*****************************************************************************/

#endif /* TEE_UTA_TRACE_H */
