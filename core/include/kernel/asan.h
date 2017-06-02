/*
 * Copyright (c) 2016, Linaro Limited
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
#ifndef __KERNEL_ASAN_H
#define __KERNEL_ASAN_H


#define ASAN_DATA_RED_ZONE	-1
#define ASAN_HEAP_RED_ZONE	-2

#define ASAN_BLOCK_SIZE		8
#define ASAN_BLOCK_SHIFT	3
#define ASAN_BLOCK_MASK		(ASAN_BLOCK_SIZE - 1)

#ifndef ASM
#include <types_ext.h>

void asan_set_shadowed(const void *va_begin, const void *va_end);
void asan_start(void);

#ifdef CFG_CORE_SANITIZE_KADDRESS
void asan_tag_no_access(const void *begin, const void *end);
void asan_tag_access(const void *begin, const void *end);
void asan_tag_heap_free(const void *begin, const void *end);
#else
static inline void asan_tag_no_access(const void *begin __unused,
				      const void *end __unused)
{
}
static inline void asan_tag_access(const void *begin __unused,
				   const void *end __unused)
{
}
static inline void asan_tag_heap_free(const void *begin __unused,
				      const void *end __unused)
{
}
#endif

#endif /*ASM*/
#endif /*__KERNEL_ASAN_H*/
