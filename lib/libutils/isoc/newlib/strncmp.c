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
	<<strncmp>>---character string compare
	
INDEX
	strncmp

ANSI_SYNOPSIS
	#include <string.h>
	int strncmp(const char *<[a]>, const char * <[b]>, size_t <[length]>);

TRAD_SYNOPSIS
	#include <string.h>
	int strncmp(<[a]>, <[b]>, <[length]>)
	char *<[a]>;
	char *<[b]>;
	size_t <[length]>

DESCRIPTION
	<<strncmp>> compares up to <[length]> characters
	from the string at <[a]> to the string at <[b]>.

RETURNS
	If <<*<[a]>>> sorts lexicographically after <<*<[b]>>>,
	<<strncmp>> returns a number greater than zero.  If the two
	strings are equivalent, <<strncmp>> returns zero.  If <<*<[a]>>>
	sorts lexicographically before <<*<[b]>>>, <<strncmp>> returns a
	number less than zero.

PORTABILITY
<<strncmp>> is ANSI C.

<<strncmp>> requires no supporting OS subroutines.

QUICKREF
	strncmp ansi pure
*/

#include "_ansi.h"
#include <string.h>
#include <limits.h>

/* Nonzero if either X or Y is not aligned on a "long" boundary.  */
#define UNALIGNED(X, Y) \
  (((long)X & (sizeof (long) - 1)) | ((long)Y & (sizeof (long) - 1)))

/* DETECTNULL returns nonzero if (long)X contains a NULL byte. */
#if LONG_MAX == 2147483647L
#define DETECTNULL(X) (((X) - 0x01010101L) & ~(X) & 0x80808080UL)
#else
#if LONG_MAX == 9223372036854775807L
#define DETECTNULL(X) (((X) - 0x0101010101010101L) & ~(X) & \
		       0x8080808080808080UL)
#else
#error long int is not a 32bit or 64bit type.
#endif
#endif

#ifndef DETECTNULL
#error long int is not a 32bit or 64bit byte
#endif

int 
_DEFUN (strncmp, (s1, s2, n),
	_CONST char *s1 _AND
	_CONST char *s2 _AND
	size_t n)
{
#if defined(PREFER_SIZE_OVER_SPEED) || defined(__OPTIMIZE_SIZE__)
  if (n == 0)
    return 0;

  while (n-- != 0 && *s1 == *s2)
    {
      if (n == 0 || *s1 == '\0')
	break;
      s1++;
      s2++;
    }

  return (*(unsigned char *) s1) - (*(unsigned char *) s2);
#else
  unsigned long *a1;
  unsigned long *a2;

  if (n == 0)
    return 0;

  /* If s1 or s2 are unaligned, then compare bytes. */
  if (!UNALIGNED (s1, s2))
    {
      /* If s1 and s2 are word-aligned, compare them a word at a time. */
      a1 = (unsigned long*)s1;
      a2 = (unsigned long*)s2;
      while (n >= sizeof (long) && *a1 == *a2)
        {
          n -= sizeof (long);

          /* If we've run out of bytes or hit a null, return zero
	     since we already know *a1 == *a2.  */
          if (n == 0 || DETECTNULL (*a1))
	    return 0;

          a1++;
          a2++;
        }

      /* A difference was detected in last few bytes of s1, so search bytewise */
      s1 = (char*)a1;
      s2 = (char*)a2;
    }

  while (n-- > 0 && *s1 == *s2)
    {
      /* If we've run out of bytes or hit a null, return zero
	 since we already know *s1 == *s2.  */
      if (n == 0 || *s1 == '\0')
	return 0;
      s1++;
      s2++;
    }
  return (*(unsigned char *) s1) - (*(unsigned char *) s2);
#endif /* not PREFER_SIZE_OVER_SPEED */
}
