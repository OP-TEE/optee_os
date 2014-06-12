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
#ifndef GUARD_MPA_CONFIG_H
#define GUARD_MPA_CONFIG_H

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>

/************************************************************************\
 *  Common definitions
 *  You should go through these carefully and adjust to your environment
 \************************************************************************/

/*
 * Definitions of different sized integers and unsigned
 *
 * mpa_word_t:  should be an unsigned int of size equal to the most
 *              efficient add/sub/mul/div word size of the machine.
 *
 * mpa_int_t    should be a signed int of the same size as the mpa_word_t
 *
 * mpa_halfw_t: half size of mpa_word_t
 *
 * mpa_asize_t: an unsigned int of suitable size to hold the number of
 *              allocated bytes for the representation. We cannot use size_t
 *              since that is 64 bit long on 64 bit machines, and that is
 *              ridiciously large.
 *
 * mpa_usize_t: a signed int suitable to hold the number of used mpa_word_t to
 *              represent the integer.
 *
 * mpa_byte_t:  the native unsigned byte type.
 */
typedef uint32_t mpa_word_t;
typedef int32_t mpa_int_t;
typedef uint16_t mpa_halfw_t;
typedef uint32_t mpa_asize_t;
typedef int32_t mpa_usize_t;
typedef uint8_t mpa_byte_t;

/* Number of bits in mpa_word_t */
#define MPA_WORD_SIZE                  32

/* Largest representable number in a mpa_int_t */
#define MPA_INT_MAX                    INT32_MAX

/* Smallest representable number in a mpa_int_t */
#define MPA_INT_MIN                    INT32_MIN

/* The Log2(MPA_WORD_SIZE) */
#define MPA_LOG_OF_WORD_SIZE           5

/* The Log2 of number of bytes in a mpa_word_t */
#define MPA_LOG_OF_BYTES_PER_WORD      2

/* The largest power of 10 representable in a mpa_word_t */
#define LARGEST_DECIMAL_BASE_IN_WORD    1000000000

/* the number of decimal digits minus 1 in LARGEST_DECIMAL_BASE_IN_WORD */
#define LARGEST_DECIMAL_BASE_DIGITS     9

/* The largest string size to represent a big number as a string */
#define MPA_STR_MAX_SIZE (4096 + 2)

/* define MPA_BIG_ENDIAN or MPA_LITTLE_ENDIAN */
#define MPA_LITTLE_ENDIAN
/*#define MPA_BIG_ENDIAN */

/*
 * comment out the line below if your system does not support "unsigned
 * long long"
 */
#define MPA_SUPPORT_DWORD_T

/*
 * define if you want to use ARM assembler code for certain cruicial
 * functions
 */
/* #define     USE_ARM_ASM */

/*
 * Include functionality for converting to and from strings; mpa_set_string
 * and mpa_get_string.
 */
#define MPA_INCLUDE_STRING_CONVERSION

/*
 * Quick fix to be able to better define these mem functions later
 */
#define MACRO_DEF_MPA_MEMFUNCS

#ifdef MACRO_DEF_MPA_MEMFUNCS
#include <stdlib.h>
#include <string.h>
#define mpa_memset  memset
#define mpa_memcpy  memcpy
#define mpa_memmove memmove
#endif

#endif /* include guard */
