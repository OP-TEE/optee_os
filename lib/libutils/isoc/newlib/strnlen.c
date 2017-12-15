// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 1994-2009  Red Hat, Inc.
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
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
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

/* 
FUNCTION
	<<strnlen>>---character string length
	
INDEX
	strnlen

ANSI_SYNOPSIS
	#include <string.h>
	size_t strnlen(const char *<[str]>, size_t <[n]>);

TRAD_SYNOPSIS
	#include <string.h>
	size_t strnlen(<[str]>, <[n]>)
	char *<[src]>;
	size_t <[n]>;

DESCRIPTION
	The <<strnlen>> function works out the length of the string
	starting at <<*<[str]>>> by counting chararacters until it
	reaches a NUL character or the maximum: <[n]> number of
        characters have been inspected.

RETURNS
	<<strnlen>> returns the character count or <[n]>.

PORTABILITY
<<strnlen>> is a GNU extension.

<<strnlen>> requires no supporting OS subroutines.

*/

#undef __STRICT_ANSI__
#include "_ansi.h"
#include <string.h>

size_t
_DEFUN (strnlen, (str, n),
	_CONST char *str _AND
	size_t n)
{
  _CONST char *start = str;

  while (n-- > 0 && *str)
    str++;

  return str - start;
}
