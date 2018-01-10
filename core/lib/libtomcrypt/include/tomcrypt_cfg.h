/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2001-2007, Tom St Denis
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

/* This is the build config file.
 *
 * With this you can setup what to inlcude/exclude automatically during any build.  Just comment
 * out the line that #define's the word for the thing you want to remove.  phew!
 */

#ifndef TOMCRYPT_CFG_H
#define TOMCRYPT_CFG_H

#if defined(_WIN32) || defined(_MSC_VER)
#define LTC_CALL __cdecl
#else
#ifndef LTC_CALL
   #define LTC_CALL
#endif
#endif

#ifndef LTC_EXPORT
#define LTC_EXPORT
#endif

/* certain platforms use macros for these, making the prototypes broken */
#ifndef LTC_NO_PROTOTYPES

/* you can change how memory allocation works ... */
LTC_EXPORT void * LTC_CALL XMALLOC(size_t n);
LTC_EXPORT void * LTC_CALL XREALLOC(void *p, size_t n);
LTC_EXPORT void * LTC_CALL XCALLOC(size_t n, size_t s);
LTC_EXPORT void LTC_CALL XFREE(void *p);

LTC_EXPORT void LTC_CALL XQSORT(void *base, size_t nmemb, size_t size, int(*compar)(const void *, const void *));


/* change the clock function too */
LTC_EXPORT clock_t LTC_CALL XCLOCK(void);

/* various other functions */
LTC_EXPORT void * LTC_CALL XMEMCPY(void *dest, const void *src, size_t n);
LTC_EXPORT int   LTC_CALL XMEMCMP(const void *s1, const void *s2, size_t n);
LTC_EXPORT void * LTC_CALL XMEMSET(void *s, int c, size_t n);

LTC_EXPORT int   LTC_CALL XSTRCMP(const char *s1, const char *s2);

#endif

/*
 * with ARGTYPE==4, LTC_ARGCHK() returns an error when an argument is not correct
 */
#define ARGTYPE  4

/* type of argument checking, 0=default, 1=fatal and 2=error+continue, 3=nothing */
#ifndef ARGTYPE
   #define ARGTYPE  0
#endif

/* Controls endianess and size of registers.  Leave uncommented to get platform neutral [slower] code 
 * 
 * Note: in order to use the optimized macros your platform must support unaligned 32 and 64 bit read/writes.
 * The x86 platforms allow this but some others [ARM for instance] do not.  On those platforms you **MUST**
 * use the portable [slower] macros.
 */

/* detect x86-32 machines somewhat */
#if !defined(__STRICT_ANSI__) && !defined(__x86_64__) && !defined(_WIN64) && ((defined(_MSC_VER) && defined(WIN32)) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__))))
   #define ENDIAN_LITTLE
   #define ENDIAN_32BITWORD
   #define LTC_FAST
#endif

/* detects MIPS R5900 processors (PS2) */
#if (defined(__R5900) || defined(R5900) || defined(__R5900__)) && (defined(_mips) || defined(__mips__) || defined(mips))
   #define ENDIAN_LITTLE
   #define ENDIAN_64BITWORD
#endif

/* detect amd64 */
#if !defined(__STRICT_ANSI__) && defined(__x86_64__)
   #define ENDIAN_LITTLE
   #define ENDIAN_64BITWORD
   #define LTC_FAST
#endif

/* detect PPC32 */
#if !defined(__STRICT_ANSI__) && defined(LTC_PPC32)
   #define ENDIAN_BIG
   #define ENDIAN_32BITWORD
   #define LTC_FAST
#endif   

/* detect sparc and sparc64 */
#if defined(__sparc__)
  #define ENDIAN_BIG
  #if defined(__arch64__)
    #define ENDIAN_64BITWORD
  #else
    #define ENDIAN_32BITWORD
  #endif
#endif


#ifdef LTC_NO_FAST
   #ifdef LTC_FAST
      #undef LTC_FAST
   #endif
#endif

#ifdef LTC_FAST
#if __GNUC__ < 4 /* if the compiler does not support gnu extensions, i.e. its neither clang nor gcc nor icc */
#error the LTC_FAST hack is only available on compilers that support __attribute__((may_alias)) - disable it for your compiler, and dont worry, it won`t buy you much anyway
#else
#ifdef ENDIAN_64BITWORD
typedef ulong64 __attribute__((__may_alias__)) LTC_FAST_TYPE;
#else
typedef ulong32 __attribute__((__may_alias__)) LTC_FAST_TYPE;
#endif
#endif
#endif /* LTC_FAST */


/* No asm is a quick way to disable anything "not portable" */
#ifdef LTC_NO_ASM
   #undef ENDIAN_LITTLE
   #undef ENDIAN_BIG
   #undef ENDIAN_32BITWORD
   #undef ENDIAN_64BITWORD
   #undef LTC_FAST
   #undef LTC_FAST_TYPE
   #define LTC_NO_ROLC
	#define LTC_NO_BSWAP
#endif

/* #define ENDIAN_LITTLE */
/* #define ENDIAN_BIG */

/* #define ENDIAN_32BITWORD */
/* #define ENDIAN_64BITWORD */

#if (defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE)) && !(defined(ENDIAN_32BITWORD) || defined(ENDIAN_64BITWORD))
    #error You must specify a word size as well as endianess in tomcrypt_cfg.h
#endif

#if !(defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE))
   #define ENDIAN_NEUTRAL
#endif

#if (defined(ENDIAN_32BITWORD) && defined(ENDIAN_64BITWORD))
    #error Can not be 32 and 64 bit words...
#endif

/* gcc 4.3 and up has a bswap builtin; detect it by gcc version.
 * clang also supports the bswap builtin, and although clang pretends
 * to be gcc (macro-wise, anyway), clang pretends to be a version
 * prior to gcc 4.3, so we can't detect bswap that way.  Instead,
 * clang has a __has_builtin mechanism that can be used to check
 * for builtins:
 * http://clang.llvm.org/docs/LanguageExtensions.html#feature_check */
#ifndef __has_builtin
   #define __has_builtin(x) 0
#endif
#if !defined(LTC_NO_BSWAP) && defined(__GNUC__) &&                      \
   ((__GNUC__ * 100 + __GNUC_MINOR__ >= 403) ||                         \
    (__has_builtin(__builtin_bswap32) && __has_builtin(__builtin_bswap64)))
   #define LTC_HAVE_BSWAP_BUILTIN
#endif

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_cfg.h,v $ */
/* $Revision: 1.19 $ */
/* $Date: 2006/12/04 02:19:48 $ */
