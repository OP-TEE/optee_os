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
	<<memcpy>>---copy memory regions

ANSI_SYNOPSIS
	#include <string.h>
	void* memcpy(void *<[out]>, const void *<[in]>, size_t <[n]>);

TRAD_SYNOPSIS
	#include <string.h>
	void *memcpy(<[out]>, <[in]>, <[n]>
	void *<[out]>;
	void *<[in]>;
	size_t <[n]>;

DESCRIPTION
	This function copies <[n]> bytes from the memory region
	pointed to by <[in]> to the memory region pointed to by
	<[out]>.

	If the regions overlap, the behavior is undefined.

RETURNS
	<<memcpy>> returns a pointer to the first byte of the <[out]>
	region.

PORTABILITY
<<memcpy>> is ANSI C.

<<memcpy>> requires no supporting OS subroutines.

QUICKREF
	memcpy ansi pure
*/

#include "_ansi.h"
#include <string.h>

/* Nonzero if either X or Y is not aligned on a "long" boundary.  */
#define UNALIGNED(X, Y) \
	(((long)X & (sizeof(long) - 1)) | ((long)Y & (sizeof(long) - 1)))

/* How many bytes are copied each iteration of the 4X unrolled loop.  */
#define BIGBLOCKSIZE    (sizeof(long) << 2)

/* How many bytes are copied each iteration of the word copy loop.  */
#define LITTLEBLOCKSIZE (sizeof(long))

/* Threshhold for punting to the byte copier.  */
#define TOO_SMALL(LEN)  ((LEN) < BIGBLOCKSIZE)

_PTR
_DEFUN(memcpy, (dst0, src0, len0), _PTR dst0 _AND _CONST _PTR src0 _AND
	 size_t len0)
{
#if defined(PREFER_SIZE_OVER_SPEED) || defined(__OPTIMIZE_SIZE__)
	char *dst = (char *)dst0;
	char *src = (char *)src0;

	_PTR save = dst0;

	while (len0--)
		*dst++ = *src++;

	return save;
#else
	char *dst = dst0;
	_CONST char *src = src0;
	long *aligned_dst;
	_CONST long *aligned_src;

	/* If the size is small, or either SRC or DST is unaligned,
	   then punt into the byte copy loop.  This should be rare.  */
	if (!TOO_SMALL(len0) && !UNALIGNED(src, dst)) {
		aligned_dst = (long *)dst;
		aligned_src = (long *)src;

		/* Copy 4X long words at a time if possible.  */
		while (len0 >= BIGBLOCKSIZE) {
			*aligned_dst++ = *aligned_src++;
			*aligned_dst++ = *aligned_src++;
			*aligned_dst++ = *aligned_src++;
			*aligned_dst++ = *aligned_src++;
			len0 -= BIGBLOCKSIZE;
		}

		/* Copy one long word at a time if possible.  */
		while (len0 >= LITTLEBLOCKSIZE) {
			*aligned_dst++ = *aligned_src++;
			len0 -= LITTLEBLOCKSIZE;
		}

		/* Pick up any residual with a byte copier.  */
		dst = (char *)aligned_dst;
		src = (char *)aligned_src;
	}

	while (len0--)
		*dst++ = *src++;

	return dst0;
#endif /* not PREFER_SIZE_OVER_SPEED */
}
