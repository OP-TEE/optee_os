/* SPDX-License-Identifier: BSD-2-Clause */
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
 *
 * Some of the defines below is known to sometimes cause conflicts when
 * this file is included from xtest in normal world. It is assumed that
 * the conflicting defines has the same meaning in that environment.
 * Surrounding the troublesome defines with #ifndef should be enough.
 */
#define __deprecated	__attribute__((deprecated))
#ifndef __packed
#define __packed	__attribute__((packed))
#endif
#define __weak		__attribute__((weak))
#ifndef __noreturn
#define __noreturn	__attribute__((noreturn))
#endif
#define __pure		__attribute__((pure))
#define __aligned(x)	__attribute__((aligned(x)))
#define __printf(a, b)	__attribute__((format(printf, a, b)))
#define __noinline	__attribute__((noinline))
#define __attr_const	__attribute__((__const__))
#ifndef __unused
#define __unused	__attribute__((unused))
#endif
#define __maybe_unused	__attribute__((unused))
#ifndef __used
#define __used		__attribute__((__used__))
#endif
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

#define __ASSIGN_OF(dest, src) (__extension__({				    \
	typeof(src) __x = (src);					    \
	typeof(dest) __y = __x;						    \
	uintmax_t __xu = __x;						    \
	uintmax_t __yu = __y;						    \
									    \
	(__xu == __yu) && ((__x < 1) == (__y < 1)) ? ((dest) = __y, 0) : 1; \
}))

#define __ADD_OF(c, a, b) (__extension__({				      \
	typeof(a) __a_a = (a);						      \
	typeof(b) __a_b = (b);						      \
	intmax_t __a_as = __a_a;					      \
	uintmax_t __a_au = __a_a;					      \
	intmax_t __a_bs = __a_b;					      \
	uintmax_t __a_bu = __a_b;					      \
									      \
	__a_b < 1 ?							      \
		__a_a < 1 ?						      \
			INTMAX_MIN - __a_bs <= __a_as ?			      \
				__ASSIGN_OF((c), __a_as + __a_bs)	      \
			:						      \
				1					      \
		:							      \
			__a_au >= (uintmax_t)-__a_b ?			      \
				__ASSIGN_OF((c), __a_au + __a_bs)	      \
			:						      \
				__ASSIGN_OF((c), (intmax_t)(__a_au + __a_bs)) \
	:								      \
		__a_a < 1 ?						      \
			__a_bu >= (uintmax_t)-__a_a ?			      \
				__ASSIGN_OF((c), __a_as + __a_bu)	      \
			:						      \
				__ASSIGN_OF((c), (intmax_t)(__a_as + __a_bu)) \
		:							      \
			UINTMAX_MAX - __a_bu >= __a_au ?		      \
				__ASSIGN_OF((c), __a_au + __a_bu)	      \
			:						      \
				1;					      \
}))

#define __SUB_OF(c, a, b) (__extension__({				      \
	typeof(a) __s_a = a;						      \
	typeof(b) __s_b = b;						      \
	intmax_t __s_as = __s_a;					      \
	uintmax_t __s_au = __s_a;					      \
	intmax_t __s_bs = __s_b;					      \
	uintmax_t __s_bu = __s_b;					      \
									      \
	__s_b < 1 ?							      \
		__s_a < 1 ?						      \
			INTMAX_MAX + __s_b >= __s_a ?			      \
				__ASSIGN_OF((c), __s_as - __s_bs)	      \
			:						      \
				1					      \
		:							      \
			(uintmax_t)(UINTMAX_MAX + __s_bs) >= __s_au ?	      \
				__ASSIGN_OF((c), __s_a - __s_b)		      \
			:						      \
				1					      \
	:								      \
		__s_a < 1 ?						      \
			INTMAX_MIN + __s_b <= __s_a ?			      \
				__ASSIGN_OF((c), (intmax_t)(__s_as - __s_bu)) \
			:						      \
				1					      \
		:							      \
			__s_bu <= __s_au ?				      \
				__ASSIGN_OF((c), __s_au - __s_bu)	      \
			:						      \
				__ASSIGN_OF((c), (intmax_t)(__s_au - __s_bu)) \
	;								      \
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
 * only uses half the capacity of the underlying type it can't overflow
 *
 * The addition of T2 and T3 can overflow so we use __ADD_OF() to
 * perform that addition. If the addition succeeds without overflow the
 * result is assigned the required sign and checked for overflow again.
 */

#define __m_negate	((__m_oa < 1) != (__m_ob < 1))
#define __m_hshift	(sizeof(uintmax_t) * 8 / 2)
#define __m_hmask	(UINTMAX_MAX >> __m_hshift)
#define __m_a0		((uintmax_t)__m_a >> __m_hshift)
#define __m_b0		((uintmax_t)__m_b >> __m_hshift)
#define __m_a1		((uintmax_t)__m_a & __m_hmask)
#define __m_b1		((uintmax_t)__m_b & __m_hmask)
#define __m_t		(__m_a1 * __m_b0 + __m_a0 * __m_b1)

#define __MUL_OF(c, a, b) (__extension__({			      \
	typeof(a) __m_oa = (a);					      \
	typeof(a) __m_a = __m_oa < 1 ? -__m_oa : __m_oa;	      \
	typeof(b) __m_ob = (b);					      \
	typeof(b) __m_b = __m_ob < 1 ? -__m_ob : __m_ob;	      \
	typeof(c) __m_c;					      \
								      \
	__m_oa == 0 || __m_ob == 0 || __m_oa == 1 || __m_ob == 1 ?    \
		__ASSIGN_OF((c), __m_oa * __m_ob)		      \
	:							      \
		(__m_a0 && __m_b0) || __m_t > __m_hmask ?	      \
			1					      \
		:						      \
			__ADD_OF(__m_c, __m_t << __m_hshift,	      \
				 __m_a1 * __m_b1) ?		      \
				1				      \
			:					      \
				__m_negate ?			      \
					__ASSIGN_OF((c), -__m_c)      \
				:				      \
					__ASSIGN_OF((c), __m_c);      \
}))

#define __compiler_add_overflow(a, b, res) __ADD_OF(*(res), (a), (b))
#define __compiler_sub_overflow(a, b, res) __SUB_OF(*(res), (a), (b))
#define __compiler_mul_overflow(a, b, res) __MUL_OF(*(res), (a), (b))

#endif /*!__HAVE_BUILTIN_OVERFLOW*/

#define __compiler_compare_and_swap(p, oval, nval) \
	__atomic_compare_exchange_n((p), (oval), (nval), true, \
				    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED) \

#define __compiler_atomic_load(p) __atomic_load_n((p), __ATOMIC_RELAXED)
#define __compiler_atomic_store(p, val) \
	__atomic_store_n((p), (val), __ATOMIC_RELAXED)

#endif /*COMPILER_H*/
