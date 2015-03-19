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
#ifndef INTTYPES_H
#define INTTYPES_H

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

#endif /*INTTYPES_H*/
