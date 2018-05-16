/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef LIMITS_H
#define LIMITS_H

#define CHAR_BIT __CHAR_BIT__

#ifdef __CHAR_UNSIGNED__
#define CHAR_MAX UCHAR_MAX
#define CHAR_MIN 0
#else
#define CHAR_MAX SCHAR_MAX
#define CHAR_MIN SCHAR_MIN
#endif

#define INT_MAX __INT_MAX__
#define INT_MIN (-INT_MAX - 1)

#define LONG_MAX __LONG_MAX__
#define LONG_MIN (-LONG_MAX - 1L)

#define LLONG_MAX __LONG_LONG_MAX__
#define LLONG_MIN (-LLONG_MAX - 1LL)

#define MB_LEN_MAX 1

#define SCHAR_MAX __SCHAR_MAX__
#define SCHAR_MIN (-SCHAR_MAX - 1)

#define SHRT_MAX __SHRT_MAX__
#define SHRT_MIN (-SHRT_MAX - 1)

#if __SCHAR_MAX__ == __INT_MAX__
#define UCHAR_MAX (SCHAR_MAX * 2U + 1U)
#else
#define UCHAR_MAX (SCHAR_MAX * 2 + 1)
#endif

#if __SHRT_MAX__ == __INT_MAX__
#define USHRT_MAX (SHRT_MAX * 2U + 1U)
#else
#define USHRT_MAX (SHRT_MAX * 2 + 1)
#endif

#define UINT_MAX (INT_MAX * 2U + 1U)

#define ULONG_MAX (LONG_MAX * 2UL + 1UL)
#define ULLONG_MAX (LLONG_MAX * 2ULL + 1ULL)

#endif /* LIMITS_H */
