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
	<<memcmp>>---compare two memory areas

INDEX
	memcmp

ANSI_SYNOPSIS
	#include <string.h>
	int memcmp(const void *<[s1]>, const void *<[s2]>, size_t <[n]>);

TRAD_SYNOPSIS
	#include <string.h>
	int memcmp(<[s1]>, <[s2]>, <[n]>)
	void *<[s1]>;
	void *<[s2]>;
	size_t <[n]>;

DESCRIPTION
	This function compares not more than <[n]> characters of the
	object pointed to by <[s1]> with the object pointed to by <[s2]>.

RETURNS
	The function returns an integer greater than, equal to or
	less than zero 	according to whether the object pointed to by
	<[s1]> is greater than, equal to or less than the object
	pointed to by <[s2]>.

PORTABILITY
<<memcmp>> is ANSI C.

<<memcmp>> requires no supporting OS subroutines.

QUICKREF
	memcmp ansi pure
*/

#include "_ansi.h"
#include <string.h>

/* Nonzero if either X or Y is not aligned on a "long" boundary.  */
#define UNALIGNED(X, Y) \
	(((long)X & (sizeof(long) - 1)) | ((long)Y & (sizeof(long) - 1)))

/* How many bytes are copied each iteration of the word copy loop.  */
#define LBLOCKSIZE (sizeof(long))

/* Threshhold for punting to the byte copier.  */
#define TOO_SMALL(LEN)  ((LEN) < LBLOCKSIZE)

int
_DEFUN(memcmp, (m1, m2, n), _CONST _PTR m1 _AND _CONST _PTR m2 _AND size_t n)
{
#if defined(PREFER_SIZE_OVER_SPEED) || defined(__OPTIMIZE_SIZE__)
	unsigned char *s1 = (unsigned char *)m1;
	unsigned char *s2 = (unsigned char *)m2;

	while (n--) {
		if (*s1 != *s2)
			return *s1 - *s2;
		s1++;
		s2++;
	}
	return 0;
#else
	unsigned char *s1 = (unsigned char *)m1;
	unsigned char *s2 = (unsigned char *)m2;
	unsigned long *a1;
	unsigned long *a2;

	/* If the size is too small, or either pointer is unaligned,
	   then we punt to the byte compare loop.  Hopefully this will
	   not turn up in inner loops.  */
	if (!TOO_SMALL(n) && !UNALIGNED(s1, s2)) {
		/*
		 * Otherwise, load and compare the blocks of memory one word at
		 * a time.
		 */
		a1 = (unsigned long *)s1;
		a2 = (unsigned long *)s2;
		while (n >= LBLOCKSIZE) {
			if (*a1 != *a2)
				break;
			a1++;
			a2++;
			n -= LBLOCKSIZE;
		}

		/* check m mod LBLOCKSIZE remaining characters */

		s1 = (unsigned char *)a1;
		s2 = (unsigned char *)a2;
	}

	while (n--) {
		if (*s1 != *s2)
			return *s1 - *s2;
		s1++;
		s2++;
	}

	return 0;
#endif /* not PREFER_SIZE_OVER_SPEED */
}
