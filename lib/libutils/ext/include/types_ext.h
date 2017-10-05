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
#ifndef TYPES_EXT_H
#define TYPES_EXT_H

#include <limits.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>
#include <unistd.h>

typedef uintptr_t uaddr_t;
#define PRIxUA	PRIxPTR

typedef uintptr_t vaddr_t;
#define PRIxVA	PRIxPTR

#if defined(__ILP32__) && defined(CFG_CORE_LARGE_PHYS_ADDR)
typedef uint64_t paddr_t;
typedef uint64_t paddr_size_t;
#define PRIxPA			PRIx64
#define PRIxPASZ		PRIx64
#define __SIZEOF_PADDR__	8
#else
typedef uintptr_t paddr_t;
typedef uintptr_t paddr_size_t;
#define PRIxPA			PRIxPTR
#define PRIxPASZ		PRIxPTR
#define __SIZEOF_PADDR__	__SIZEOF_POINTER__
#endif

#endif /* TYPES_EXT_H */
