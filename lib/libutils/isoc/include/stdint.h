/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <limits.h>

/*
 * This file provides what C99 standard requires in
 * 7.18 interger types <stdint.h>
 */

#ifndef STDINT_H
#define STDINT_H
#define _STDINT_H

/*
 * If compiler supplies neither __ILP32__ or __LP64__, try to figure it out
 * here.
 */
#if !defined(__ILP32__) && !defined(__LP64__)
#if defined(__SIZEOF_INT__) && defined(__SIZEOF_POINTER__) && \
	defined(__SIZEOF_LONG__)
#if __SIZEOF_INT__ == 4 && __SIZEOF_POINTER__ == 4 && __SIZEOF_LONG__ == 4
#define __ILP32__ 1
#endif
#if __SIZEOF_INT__ == 4 && __SIZEOF_POINTER__ == 8 && __SIZEOF_LONG__ == 8
#define __LP64__ 1
#endif
#endif
#endif /* !defined(__ILP32__) && !defined(__LP64__) */

#if !defined(__ILP32__) && !defined(__LP64__)
#error Neither __ILP32__ nor __LP64__ is defined
#endif

#ifndef __ASSEMBLER__

/* 7.18.1.1 Exact-width interger types */
#ifndef __int8_t_defined
# define __int8_t_defined
typedef signed char             int8_t;
typedef short int               int16_t;
typedef int                     int32_t;
#ifdef __ILP32__
__extension__
typedef long long int           int64_t;
#endif /*__ILP32__*/
#ifdef __LP64__
typedef long int		int64_t;
#endif /*__LP64__*/
#endif

/* Unsigned.  */
typedef unsigned char           uint8_t;
typedef unsigned short int      uint16_t;
#ifndef __uint32_t_defined
typedef unsigned int            uint32_t;
# define __uint32_t_defined
#endif
#ifdef __ILP32__
__extension__
typedef unsigned long long int  uint64_t;
#endif /*__ILP32__*/
#ifdef __LP64__
typedef unsigned long int	uint64_t;
#endif /*__LP64__*/

/* 7.18.1.2 Minimum-width integer types */
typedef int8_t int_least8_t;
typedef int16_t int_least16_t;
typedef int32_t int_least32_t;
typedef int64_t int_least64_t;
typedef uint8_t uint_least8_t;
typedef uint16_t uint_least16_t;
typedef uint32_t uint_least32_t;
typedef uint64_t uint_least64_t;

/* 7.18.1.3 Fastest minimum-width integer types */
typedef int8_t int_fast8_t;
typedef int16_t int_fast16_t;
typedef int32_t int_fast32_t;
typedef int64_t int_fast64_t;
typedef uint8_t uint_fast8_t;
typedef uint16_t uint_fast16_t;
typedef uint32_t uint_fast32_t;
typedef uint64_t uint_fast64_t;

/* 7.18.1.4 Integer types capable of holding object pointers */
typedef long intptr_t;
typedef unsigned long uintptr_t;

typedef int64_t intmax_t;
typedef uint64_t uintmax_t;

#endif /*__ASSEMBLER__*/

/*
 * 7.18.2 Limits of specified-width integer types
 */

/* 7.18.2.1 Limits of exact-width interger types */

#define INT8_MIN    (-0x7f-1)
#define INT16_MIN   (-0x7fff-1)
#define INT32_MIN   (-0x7fffffff-1)
#define INT64_MIN   (-0x7fffffffffffffffL-1)

#define INT8_MAX    0x7f
#define INT16_MAX   0x7fff
#define INT32_MAX   0x7fffffff
#define INT64_MAX   0x7fffffffffffffffL

#define UINT8_MAX    0xff
#define UINT16_MAX   0xffff
#define UINT32_MAX   0xffffffffU
#define UINT64_MAX   0xffffffffffffffffUL

/* 7.18.2.2 Limits of minimum-width integer types */

#define INT_LEAST8_MIN		INT8_MIN
#define INT_LEAST16_MIN		INT16_MIN
#define INT_LEAST32_MIN		INT32_MIN
#define INT_LEAST64_MIN		INT64_MIN

#define INT_LEAST8_MAX		INT8_MAX
#define INT_LEAST16_MAX		INT16_MAX
#define INT_LEAST32_MAX		INT32_MAX
#define INT_LEAST64_MAX		INT64_MAX

#define UINT_LEAST8_MAX		UINT8_MAX
#define UINT_LEAST16_MAX	UINT16_MAX
#define UINT_LEAST32_MAX	UINT32_MAX
#define UINT_LEAST64_MAX	UINT64_MAX

/* 7.18.2.3 Limits of fastest minimum-width integer types */

#define INT_FAST8_MIN		INT8_MIN
#define INT_FAST16_MIN		INT16_MIN
#define INT_FAST32_MIN		INT32_MIN
#define INT_FAST64_MIN		INT64_MIN

#define INT_FAST8_MAX		INT8_MAX
#define INT_FAST16_MAX		INT16_MAX
#define INT_FAST32_MAX		INT32_MAX
#define INT_FAST64_MAX		INT64_MAX

#define UINT_FAST8_MAX		UINT8_MAX
#define UINT_FAST16_MAX		UINT16_MAX
#define UINT_FAST32_MAX		UINT32_MAX
#define UINT_FAST64_MAX		UINT64_MAX

/* 7.18.2.4 Limits of integer types capable of holding object pointers */

#define INTPTR_MIN  LONG_MIN
#define INTPTR_MAX  LONG_MAX
#define UINTPTR_MAX ULONG_MAX

/* 7.18.2.5  Limits of greatest-width integer types */
#define INTMAX_MAX  INT64_MAX
#define INTMAX_MIN  INT64_MIN
#define UINTMAX_MAX UINT64_MAX

/* 7.18.3  Limits of other integer types */
#define SIZE_MAX	ULONG_MAX

/*
 * 7.18.4 Macros for integer constants
 */

#ifdef __ASSEMBLER__
#define U(v)		v
#define UL(v)		v
#define ULL(v)		v
#define L(v)		v
#define LL(v)		v
#else
#define U(v)		v ## U
#define UL(v)		v ## UL
#define ULL(v)		v ## ULL
#define L(v)		v ## L
#define LL(v)		v ## LL
#endif

/* 7.18.4.1 Macros for minimum-width integer constants */

#define INT8_C(v)	v
#define UINT8_C(v)	v
#define INT16_C(v)	v
#define UINT16_C(v)	v
#define INT32_C(v)	v
#define UINT32_C(v)	U(v)
#ifdef __ILP32__
#define INT64_C(v)	LL(v)
#define UINT64_C(v)	ULL(v)
#endif
#ifdef __LP64__
#define INT64_C(v)	L(v)
#define UINT64_C(v)	UL(v)
#endif

#define UINTPTR_C(v)	UL(v)

/* 7.18.4.2 Macros for greatest-width integer constants */

#define INTMAX_C(v)	INT64_C(v)
#define UINTMAX_C(v)	UINT64_C(v)

#endif /* STDINT_H */
