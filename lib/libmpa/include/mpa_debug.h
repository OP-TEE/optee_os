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
#ifndef GUARD_MPA_DEBUG_H
#define GUARD_MPA_DEBUG_H

#include "mpa.h"

#if defined(DEBUG)

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <trace.h>

/* console debug function declaration */
void __mpa_dbg_print_stack(void);

void __mpa_dbg_print_header(const char *f_str, const int l_num);
void __mpa_dbg_print_mpanum_hexstr(const mpanum a);
void __mpa_dbg_dump_mpanum(const mpanum val);

#endif /* defined (DEBUG) */

/*
 *  If DEBUG is defined we expand into a two-stage rocket and first print the
 *  calling function and the line, then print the debug message.
 */

#if defined(DEBUG) && defined(DEBUG_ME)

#define DPRINT_STACK __mpa_dbg_print_stack
#define DPRINT_WHERE \
	__mpa_dbg_print_header(__func__, __LINE__);

#define DPRINT   \
	DPRINT_WHERE \
	DMSG_RAW
#define DPRINT_MPANUM_HEXSTR(h, v, f) \
	do { \
		DPRINT_WHERE \
		DMSG_RAW("%s ", (h));\
		__mpa_dbg_print_mpanum_hexstr((v));\
		DMSG_RAW(" %s", (f)); \
	} while (0)
#define DPRINT_DUMP_MPANUM(h, v) \
	do { \
		DPRINT_WHERE\
		DMSG_RAW("%s ", (h));\
		__mpa_dbg_dump_mpanum((v)) \
	} while (0)

#else /* !defined(DEBUG && DEBUG_ME) */

#define DPRINT_STACK \
	do { \
		if (0) \
			((void (*)())(NULL)); \
	} while (0)

#define DPRINT if (0) ((void (*)(const char*, ...))(NULL))

#define DPRINT_MPANUM_HEXSTR \
	do { \
		if (0) \
			((void (*)(const char *h_str, const mpanum val, \
				   const char *f_str))(NULL)) \
	} while (0)

#define DPRINT_DUMP_MPANUM \
	do { \
		if (0) \
			((void (*)(const char *h_str, \
				   const mpanum val))(NULL)); \
	} while (0)
#endif /* !defined(DEBUG && DEBUG_ME) */

#endif /* include guard */
