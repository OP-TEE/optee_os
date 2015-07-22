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
#include "mpa.h"
#include "mpa_debug.h"

#if defined(DEBUG)

FILE *logfd = stdout;

#if defined(__x86_64)
#include <execinfo.h>
/*------------------------------------------------------------
 *
 *   __mpa_dbg_print_stack
 *
 */
void __mpa_dbg_print_stack()
{
	fprintf(logfd, "Cannot print stack with __x86_64\n");
}
#else
void __mpa_dbg_print_stack()
{
	fprintf(logfd, "Cannot print stack. (execinfo.h not included)\n");
}
#endif

/*  --------------------------------------------------------------------
 *  Function:  __mpa_dbg_print_header
 *  Used to print the filename and line number before DPRINTs
 *
 */
void __mpa_dbg_print_header(const char *f_str, const int l_num)
{
	fprintf(logfd, "DEBUG: %s:%d:", f_str, l_num);
	fflush(logfd);
}

/*  --------------------------------------------------------------------
 *  Function:  __mpa_dbg_print
 *
 *
 */
void __mpa_dbg_print(const char *format, ...)
{
	va_list varg;
	va_start(varg, format);
	vfprintf(logfd, format, varg);
	va_end(varg);
	fflush(logfd);
}

/*  --------------------------------------------------------------------
 *  Function:  __mpa_dbg_dump_mpanum
 *  Prints the internal values of a TEE_BigInt
 *
 */
void __mpa_dbg_dump_mpanum(mpanum a)
{
	int i;

	fprintf(logfd, " ---- Dump :\n");
	fprintf(logfd, " mpanum->size = %d\n", a->size);
	fprintf(logfd, " mpanum->alloc = %u\n", a->alloc);
	fprintf(logfd, " mpanum->d (MSW to LSW) :\n");
	for (i = __mpanum_alloced(a) - 1; i >= __mpanum_size(a); i--)
		fprintf(logfd, "%.8X ", a->d[i]);
	fprintf(logfd, "\n");
	for (i = __mpanum_size(a) - 1; i >= 0; i--)
		fprintf(logfd, "[%d] : %.8X\n", i, a->d[i]);
	fflush(logfd);
}

/*  --------------------------------------------------------------------
 *  __mpa_dbg_print_mpanum_hex. Prints the value of a in hex.
 *
 */
void __mpa_dbg_print_mpanum_hexstr(const mpanum val)
{
	static char _str_[MPA_STR_MAX_SIZE];
	mpa_get_str(_str_, MPA_STRING_MODE_HEX_UC, val);
	fprintf(logfd, "%s", _str_);
	fflush(logfd);
}

#endif
