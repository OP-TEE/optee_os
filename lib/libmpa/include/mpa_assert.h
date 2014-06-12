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
#ifndef GUARD_MPA_ASSERT_H
#define GUARD_MPA_ASSERT_H

#include "mpa_debug.h"

#if defined(DEBUG)

#define ASSERT_DO(cond, str) \
	do { \
		if (!(cond)) { \
			__mpa_dbg_print_header(__func__, __LINE__); \
			__mpa_dbg_print("Assertion failed. Msg: %s\n", \
					(str)); \
			__mpa_dbg_print_header(__func__, __LINE__); \
			__mpa_dbg_print( \
				"Program will exit, waiting for keypress.\n"); \
			fflush(stdout); \
			getchar(); \
			exit(1); \
		} \
	} while (0)

#define ASSERT(cond, str) ASSERT_DO(cond, str)

#else

#define ASSERT_DO(cond, str) \
	do { \
		if (!(cond)) { \
			while (1) \
				; \
		} \
	} while (0)

#define ASSERT(cond, str) ASSERT_DO(cond, str)
/*
 * Must stop on assert
 * #define ASSERT if (0) ((void (*)(const int cond, const char *str))(NULL))
 */
#endif

#endif /* include guard */
