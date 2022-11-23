/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __TYPES_EXT_H
#define __TYPES_EXT_H

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

#define PRIxVA_WIDTH	((int)(sizeof(vaddr_t) * 2))
#define PRIxPA_WIDTH	((int)(sizeof(paddr_t) * 2))

#endif /* __TYPES_EXT_H */
