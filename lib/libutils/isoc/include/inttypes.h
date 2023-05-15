/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __INTTYPES_H
#define __INTTYPES_H

#include <stdint.h>

#ifdef __ILP32__
#define __PRI64_PREFIX	"ll"
#endif
#ifdef __LP64__
#define __PRI64_PREFIX	"l"
#endif
#define __PRIPTR_PREFIX "l"

#define PRId8		"d"
#define PRId16		"d"
#define PRId32		"d"
#define PRId64		__PRI64_PREFIX "d"
#define PRIdPTR		__PRIPTR_PREFIX "d"

#define PRIi8		"i"
#define PRIi16		"i"
#define PRIi32		"i"
#define PRIi64		__PRI64_PREFIX "i"
#define PRIiPTR		__PRIPTR_PREFIX "i"

#define PRIo8		"o"
#define PRIo16		"o"
#define PRIo32		"o"
#define PRIo64		__PRI64_PREFIX "o"
#define PRIoPTR		__PRIPTR_PREFIX "o"

#define PRIu8		"u"
#define PRIu16		"u"
#define PRIu32		"u"
#define PRIu64		__PRI64_PREFIX "u"
#define PRIuPTR		__PRIPTR_PREFIX "u"

#define PRIx8		"x"
#define PRIx16		"x"
#define PRIx32		"x"
#define PRIx64		__PRI64_PREFIX "x"
#define PRIxPTR		__PRIPTR_PREFIX "x"

#define PRIX8		"X"
#define PRIX16		"X"
#define PRIX32		"X"
#define PRIX64		__PRI64_PREFIX "X"
#define PRIXPTR		__PRIPTR_PREFIX "X"

#endif /*__INTTYPES_H*/
