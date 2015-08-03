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

/*------------------------------------------------------------
 *
 *   __mpa_dbg_print_stack
 *
 */
void __mpa_dbg_print_stack(void)
{
	MSG_RAW("Cannot print stack with __x86_64\n");
}

/*  --------------------------------------------------------------------
 *  Function:  __mpa_dbg_print_header
 *  Used to print the filename and line number before DPRINTs
 *
 */
void __mpa_dbg_print_header(const char *f_str, const int l_num)
{
	MSG_RAW("DEBUG: %s:%d:", f_str, l_num);
}

/*  --------------------------------------------------------------------
 *  Function:  __mpa_dbg_dump_mpanum
 *  Prints the internal values of a TEE_BigInt
 *
 */
void __mpa_dbg_dump_mpanum(mpanum a)
{
	int i;

	MSG_RAW(" ---- Dump :\n");
	MSG_RAW(" mpanum->size = %d\n", a->size);
	MSG_RAW(" mpanum->alloc = %u\n", a->alloc);
	MSG_RAW(" mpanum->d (MSW to LSW) :\n");
	for (i = __mpanum_alloced(a) - 1; i >= __mpanum_size(a); i--)
		MSG_RAW("%.8X ", a->d[i]);
	MSG_RAW("\n");
	for (i = __mpanum_size(a) - 1; i >= 0; i--)
		MSG_RAW("[%d] : %.8X\n", i, a->d[i]);
}

/*  --------------------------------------------------------------------
 *  __mpa_dbg_print_mpanum_hex. Prints the value of a in hex.
 *
 */
void __mpa_dbg_print_mpanum_hexstr(const mpanum val)
{
	static char _str_[MPA_STR_MAX_SIZE];
	mpa_get_str(_str_, MPA_STRING_MODE_HEX_UC, val);
	MSG_RAW("%s", _str_);
}

#endif
