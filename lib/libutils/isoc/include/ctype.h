/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef __CTYPE_H
#define __CTYPE_H

#ifndef __has_builtin
/* GCC */
#define __has_builtin(x) 1
#endif

#if __has_builtin(__builtin_isalnum)
#define isalnum(__c) __builtin_isalnum(__c)
#else
int isalnum(int c);
#endif
#if __has_builtin(__builtin_isalpha)
#define isalpha(__c) __builtin_isalpha(__c)
#else
int isalpha(int c);
#endif
#if __has_builtin(__builtin_iscntrl)
#define iscntrl(__c) __builtin_iscntrl(__c)
#else
int iscntrl(int c);
#endif
#if __has_builtin(__builtin_isdigit)
#define isdigit(__c) __builtin_isdigit(__c)
#else
int isdigit(int c);
#endif
#if __has_builtin(__builtin_isgraph)
#define isgraph(__c) __builtin_isgraph(__c)
#else
int isgraph(int c);
#endif
#if __has_builtin(__builtin_islower)
#define islower(__c) __builtin_islower(__c)
#else
int islower(int c);
#endif
#if __has_builtin(__builtin_isprint)
#define isprint(__c) __builtin_isprint(__c)
#else
int isprint(int c);
#endif
#if __has_builtin(__builtin_ispunct)
#define ispunct(__c) __builtin_ispunct(__c)
#else
int ispunct(int c);
#endif
#if __has_builtin(__builtin_isspace)
#define isspace(__c) __builtin_isspace(__c)
#else
int isspace(int c);
#endif
#if __has_builtin(__builtin_isupper)
#define isupper(__c) __builtin_isupper(__c)
#else
int isupper(int c);
#endif
#if __has_builtin(__builtin_isxdigit)
#define isxdigit(__c) __builtin_isxdigit(__c)
#else
int isxdigit(int c);
#endif
#if __has_builtin(__builtin_tolower)
#define tolower(__c) __builtin_tolower(__c)
#else
int tolower(int c);
#endif
#if __has_builtin(__builtin_toupper)
#define toupper(__c) __builtin_toupper(__c)
#else
int toupper(int c);
#endif

#endif /*__CTYPE_H*/
