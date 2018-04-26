/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef __CTYPE_H
#define __CTYPE_H

#define isalpha(__c)	__builtin_isalpha(__c)
#define isupper(__c)	__builtin_isupper(__c)
#define islower(__c)	__builtin_islower(__c)
#define isdigit(__c)	__builtin_isdigit(__c)
#define isxdigit(__c)	__builtin_isxdigit(__c)
#define isspace(__c)	__builtin_isspace(__c)
#define ispunct(__c)	__builtin_ispunct(__c)
#define isalnum(__c)	__builtin_isalnum(__c)
#define isprint(__c)	__builtin_isprint(__c)
#define isgraph(__c)	__builtin_isgraph(__c)
#define iscntrl(__c)	__builtin_iscntrl(__c)

#define toupper(__c)	__builtin_toupper(__c)
#define tolower(__c)	__builtin_tolower(__c)

#endif /*__CTYPE_H*/
