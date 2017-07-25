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

#ifndef COMPILER_H
#define COMPILER_H

/*
 * Macros that should be used instead of using __attribute__ directly to
 * ease portability and make the code easier to read.
 */

#define __deprecated	__attribute__((deprecated))
#define __packed	__attribute__((packed))
#define __weak		__attribute__((weak))
#define __noreturn	__attribute__((noreturn))
#define __pure		__attribute__((pure))
#define __aligned(x)	__attribute__((aligned(x)))
#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define __noinline	__attribute__((noinline))
#define __attr_const	__attribute__((__const__))
#define __unused	__attribute__((unused))
#define __maybe_unused	__attribute__((unused))
#define __used		__attribute__((__used__))
#define __must_check	__attribute__((warn_unused_result))
#define __cold		__attribute__((__cold__))
#define __section(x)	__attribute__((section(x)))
#define __data		__section(".data")
#define __bss		__section(".bss")
#define __rodata	__section(".rodata")
#define __rodata_unpaged __section(".rodata.__unpaged")
#define __early_ta	__section(".rodata.early_ta")
#define __noprof	__attribute__((no_instrument_function))

#define __compiler_bswap64(x)	__builtin_bswap64((x))
#define __compiler_bswap32(x)	__builtin_bswap32((x))
#define __compiler_bswap16(x)	__builtin_bswap16((x))

#define __GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + \
		       __GNUC_PATCHLEVEL__)

#if __GCC_VERSION >= 50100 && !defined(__CHECKER__)
#define __HAVE_BUILTIN_OVERFLOW 1
#endif

#ifdef __HAVE_BUILTIN_OVERFLOW
#define __compiler_add_overflow(a, b, res) \
	__builtin_add_overflow((a), (b), (res))

#define __compiler_sub_overflow(a, b, res) \
	__builtin_sub_overflow((a), (b), (res))

#define __compiler_mul_overflow(a, b, res) \
	__builtin_mul_overflow((a), (b), (res))
#else /*!__HAVE_BUILTIN_OVERFLOW*/

/*
 * Copied/inspired from https://www.fefe.de/intof.html
 */
#define __INTOF_HALF_MAX_SIGNED(type) ((type)1 << (sizeof(type)*8-2))
#define __INTOF_MAX_SIGNED(type) (__INTOF_HALF_MAX_SIGNED(type) - 1 + \
			    __INTOF_HALF_MAX_SIGNED(type))
#define __INTOF_MIN_SIGNED(type) (-1 - __INTOF_MAX_SIGNED(type))

#define __INTOF_MIN(type) ((type)-1 < 1?__INTOF_MIN_SIGNED(type):(type)0)
#define __INTOF_MAX(type) ((type)~__INTOF_MIN(type))

#define __INTOF_ASSIGN(dest, src) (__extension__({ \
	typeof(src) __intof_x = (src); \
	typeof(dest) __intof_y = __intof_x; \
	(((uintmax_t)__intof_x == (uintmax_t)__intof_y) && \
	 ((__intof_x < 1) == (__intof_y < 1)) ? \
		(void)((dest) = __intof_y) , 0 : 1); \
}))

#define __INTOF_ADD(c, a, b) (__extension__({ \
	typeof(a) __intofa_a = (a); \
	typeof(b) __intofa_b = (b); \
	\
	__intofa_b < 1 ? \
		((__INTOF_MIN(typeof(c)) - __intofa_b <= __intofa_a) ? \
			__INTOF_ASSIGN((c), __intofa_a + __intofa_b) : 1) : \
		((__INTOF_MAX(typeof(c)) - __intofa_b >= __intofa_a) ? \
			__INTOF_ASSIGN((c), __intofa_a + __intofa_b) : 1); \
}))

#define __INTOF_SUB(c, a, b) (__extension__({ \
	typeof(a) __intofs_a = a; \
	typeof(b) __intofs_b = b; \
	\
	__intofs_b < 1 ? \
		((__INTOF_MAX(typeof(c)) + __intofs_b >= __intofs_a) ? \
			__INTOF_ASSIGN((c), __intofs_a - __intofs_b) : 1) : \
		((__INTOF_MIN(typeof(c)) + __intofs_b <= __intofs_a) ? \
			__INTOF_ASSIGN((c), __intofs_a - __intofs_b) : 1); \
}))

/*
 * Dealing with detecting overflow in multiplication of integers.
 *
 * First step is to remove two corner cases with the minum signed integer
 * which can't be represented as a positive integer + sign.
 * Multiply with 0 or 1 can't overflow, no checking needed of the operation,
 * only if it can be assigned to the result.
 *
 * After the corner cases are eliminated we convert the two factors to
 * positive unsigned values, keeping track of the original in another
 * variable which is used at the end to determine the sign of the product.
 *
 * The two terms (a and b) are divided into upper and lower half (x1 upper
 * and x0 lower), so the product is:
 * ((a1 << hshift) + a0) * ((b1 << hshift) + b0)
 * which also is:
 * ((a1 * b1) << (hshift * 2)) +				(T1)
 * ((a1 * b0 + a0 * b1) << hshift) +				(T2)
 * (a0 * b0)							(T3)
 *
 * From this we can tell and (a1 * b1) has to be 0 or we'll overflow, that
 * is, at least one of a1 or b1 has to be 0. Once this has been checked the
 * addition: ((a1 * b0) << hshift) + ((a0 * b1) << hshift)
 * isn't an addition as one of the terms will be 0.
 *
 * Since each factor in: (a0 * b0)
 * only uses half the capicity of the underlaying type it can't overflow
 *
 * The addition of T2 and T3 can overflow so we use __INTOF_ADD() to
 * perform that addition. If the addition succeeds without overflow the
 * result is assigned the required sign and checked for overflow again.
 */

#define __intof_mul_negate	((__intof_oa < 1) != (__intof_ob < 1))
#define __intof_mul_hshift	(sizeof(uintmax_t) * 8 / 2)
#define __intof_mul_hmask	(UINTMAX_MAX >> __intof_mul_hshift)
#define __intof_mul_a0		((uintmax_t)(__intof_a) >> __intof_mul_hshift)
#define __intof_mul_b0		((uintmax_t)(__intof_b) >> __intof_mul_hshift)
#define __intof_mul_a1		((uintmax_t)(__intof_a) & __intof_mul_hmask)
#define __intof_mul_b1		((uintmax_t)(__intof_b) & __intof_mul_hmask)
#define __intof_mul_t		(__intof_mul_a1 * __intof_mul_b0 + \
				 __intof_mul_a0 * __intof_mul_b1)

#define __INTOF_MUL(c, a, b) (__extension__({ \
	typeof(a) __intof_oa = (a); \
	typeof(a) __intof_a = __intof_oa < 1 ? -__intof_oa : __intof_oa; \
	typeof(b) __intof_ob = (b); \
	typeof(b) __intof_b = __intof_ob < 1 ? -__intof_ob : __intof_ob; \
	typeof(c) __intof_c; \
	\
	__intof_oa == 0 || __intof_ob == 0 || \
	__intof_oa == 1 || __intof_ob == 1 ? \
		__INTOF_ASSIGN((c), __intof_oa * __intof_ob) : \
	(__intof_mul_a0 && __intof_mul_b0) || \
	 __intof_mul_t > __intof_mul_hmask ?  1 : \
	__INTOF_ADD((__intof_c), __intof_mul_t << __intof_mul_hshift, \
				 __intof_mul_a1 * __intof_mul_b1) ? 1 : \
	__intof_mul_negate ? __INTOF_ASSIGN((c), -__intof_c) : \
			     __INTOF_ASSIGN((c), __intof_c); \
}))

#define __compiler_add_overflow(a, b, res) __INTOF_ADD(*(res), (a), (b))
#define __compiler_sub_overflow(a, b, res) __INTOF_SUB(*(res), (a), (b))
#define __compiler_mul_overflow(a, b, res) __INTOF_MUL(*(res), (a), (b))

#endif /*!__HAVE_BUILTIN_OVERFLOW*/

#endif /*COMPILER_H*/
