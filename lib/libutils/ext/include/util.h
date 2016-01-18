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
#ifndef UTIL_H
#define UTIL_H

#ifndef MAX
#define MAX(a, b) \
	(__extension__({ __typeof__(a) _a = (a); \
	   __typeof__(b) _b = (b); \
	 _a > _b ? _a : _b; }))

#define MIN(a, b) \
	(__extension__({ __typeof__(a) _a = (a); \
	   __typeof__(b) _b = (b); \
	 _a < _b ? _a : _b; }))
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Round up the even multiple of size, size has to be a multiple of 2 */
#define ROUNDUP(v, size) (((v) + ((size) - 1)) & ~((size) - 1))

/* Round down the even multiple of size, size has to be a multiple of 2 */
#define ROUNDDOWN(v, size) ((v) & ~((size) - 1))

/* x has to be of an unsigned type */
#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & (~(x) + 1)) == (x)))

#define ALIGNMENT_IS_OK(p, type) \
	(((uintptr_t)(p) & (__alignof__(type) - 1)) == 0)

#define TO_STR(x) _TO_STR(x)
#define _TO_STR(x) #x

#define container_of(ptr, type, member) \
	(__extension__({ \
		const typeof(((type *)0)->member) *__ptr = (ptr); \
		(type *)((unsigned long)(__ptr) - offsetof(type, member)); \
	}))



#endif /*UTIL_H*/
