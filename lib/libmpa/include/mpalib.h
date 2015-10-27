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
#ifndef GUARD_MPALIB_H
#define GUARD_MPALIB_H

/*************************************************************
 *
 *   How functions are exported.
 *
 *************************************************************/
#define MPALIB_EXPORT

/*************************************************************
 *
 *   Include common configuration definitions
 *
 *************************************************************/
#include "mpalib_config.h"

/*************************************************************
 *
 *   TYPE DEFINITIONS
 *
 *************************************************************/

#if defined(MPA_SUPPORT_DWORD_T)
typedef unsigned long long mpa_dword_t;
#endif

/*! \struct mpa_numbase_struct
 * The internal representation of a multi precision integer.
 *
 *  \param alloc  The size of the allocated array d in number of mpa_word_t.
 *
 *  \param size   The number of used words in *d to represent the number, or
 *		  minus the number if the mpa_numbase is representing a
 *		  negative number. The mpa_numbase
 *                is representing zero if and only if size == 0.
 *
 *  \param d      The digits of the integer. The digits are in radix
 *		  2^WORD_SIZE.
 *                The digits are stored in a little endian format, i.e.
 *                the least significant word_t is stored in d[0].
 *
 * \internal ** NOTE **
 * If you change this struct, you must update the const variables
 * in mpa_misc.c and mpa_primetest.c
 * And the
 * MPA_NUMBASE_METADATA_SIZE_IN_U32
 * below.
 */
typedef struct mpa_numbase_struct {
	mpa_asize_t alloc;
	mpa_usize_t size;
	mpa_word_t d[];
} mpa_num_base;

/*/ mpanum is the type we use as parameters to function calls in this library */
typedef mpa_num_base *mpanum;

/*!
 * The Context struct for a Montgomery multiplication
 *
 * \internal ** NOTE **
 * If you change this struct, you must update the
 * MPA_FMM_CONTEXT_METADATA_SIZE_IN_U32
 * below.
 *
 */
typedef struct mpa_fmm_context_struct {
	mpanum r_ptr;
	mpanum r2_ptr;
	mpa_word_t n_inv;
	uint32_t m[];
} mpa_fmm_context_base;

typedef mpa_fmm_context_base *mpa_fmm_context;

struct mpa_scratch_mem_sync;
typedef void (mpa_scratch_mem_sync_fn)(struct mpa_scratch_mem_sync *sync);

typedef struct mpa_scratch_mem_struct {
	uint32_t size;	/* size of the memory pool, in bytes */
	uint32_t bn_bits; /* default size of a temporary variables */
	uint32_t last_offset;	/* offset to the last one */
	mpa_scratch_mem_sync_fn *get;
	mpa_scratch_mem_sync_fn *put;
	struct mpa_scratch_mem_sync *sync;
	uint32_t m[];		/* mpa_scratch_item are stored there */
} mpa_scratch_mem_base;
typedef mpa_scratch_mem_base *mpa_scratch_mem;

struct mpa_scratch_item {
	uint32_t size;		/* total size of this item */
	/* the offset of the previous and next mpa_scratch_item */
	uint32_t prev_item_offset;
	uint32_t next_item_offset;
	/* followed by a mpa_num_base, being the big number to save */
};

/*************************************************************
 *
 *   EXPORTED VARIABLES
 *
 *************************************************************/

/*************************************************************
 *
 *   MACROS
 *
 *************************************************************/

#define MPA_STRING_MODE_HEX_UC  16
#define MPA_STRING_MODE_HEX_LC  17

#define MPA_EVEN_PARITY 0
#define MPA_ODD_PARITY  1

/*! Returns true if the mpanum 'a' is even (zero included) */
#define mpa_is_even(a) (mpa_parity((a)) == MPA_EVEN_PARITY)
/*! Returns true if the mpanum 'a' is odd */
#define mpa_is_odd(a)  (mpa_parity((a)) == MPA_ODD_PARITY)
/* Short hand for setting the value of 'a' to the value of 'b' */
#define mpa_set(a, b) mpa_copy((a), (b))

/* */
/* Define how to convert between sizes given in uint32_t and mpa_word_t */
/* */
#define ASIZE_TO_U32(x) (((sizeof(mpa_word_t) * (x)) + 3) / 4)
#define U32_TO_ASIZE(x) \
	((mpa_asize_t)(((4 * (x)) + (sizeof(mpa_word_t) - 1)) / \
		sizeof(mpa_word_t)))

/*************************************************************
 *
 *   STATIC MEMORY MODE DEFINES
 *
 *************************************************************/

/*
 *   The number of extra uint32_t in the internal representation.
 *   This is used in the static memory mode.
 *   It is chosen to be complient with the requirments of GlobalPlatform.
 */
#define MPA_NUMBASE_METADATA_SIZE_IN_U32 2

#define MPA_SCRATCHMEM_METADATA_SIZE_IN_U32  (sizeof(mpa_scratch_mem_base)/ 4)

/*
 * The size (in uint32_t) of the constituent variables
 * of mpa_fmm_context apart from m[]
 */

#define MPA_FMM_CONTEXT_METADATA_SIZE_IN_U32 (sizeof(mpa_fmm_context_base)/4)

/*
 * This macro returns the size of the complete mpa_num_base struct that
 * can hold n-bits integers. This is used in the static memory mode.
 */
#define mpa_StaticVarSizeInU32(n)  \
	((((n)+31)/32) + MPA_NUMBASE_METADATA_SIZE_IN_U32)

/*
 *
 */
#define mpa_StaticTempVarSizeInU32(max_bits) \
	(2 * mpa_StaticVarSizeInU32((max_bits)) - \
	 MPA_NUMBASE_METADATA_SIZE_IN_U32)

/*
 *
 */
#define mpa_scratch_mem_size_in_U32(nr_temp_vars, max_bits) \
	(((nr_temp_vars) * (mpa_StaticTempVarSizeInU32((max_bits)) + \
			sizeof(struct mpa_scratch_item))) + \
	  sizeof(struct mpa_scratch_mem_struct))

/*
 *
 */
#define mpa_fmm_context_size_in_U32(n) \
	(2 * (mpa_StaticVarSizeInU32((n)) + 2) + \
	 MPA_FMM_CONTEXT_METADATA_SIZE_IN_U32)

/*************************************************************
 *
 *   FUNCTION PROTOTYPES
 *
 *  All externally available functions from this lib.
 *
 *************************************************************/

/*
 * From mpa_init.c
 */

/*
 * mpa_init_scratch_mem
 * Initiate a chunk of memory to be used as a scratch pool.
 * The size of the pool (in uint32_t) must corresponde to the
 * size returned by the macro mpa_ScratchMemSizeInU32
 * with the same parameters 'nr_vars' and 'max_bits'
 *
 * \param pool         The pool to initialize
 * \param size         the size, in bytes, of the pool
 * \prama bn_bits      default size, in bits, of a big number
 * \param get          increase reference counter to pool
 * \param put          decrease reference counter to pool
 * \param sync         argument to supply to get() and put()
 */
MPALIB_EXPORT void mpa_init_scratch_mem_sync(mpa_scratch_mem pool, size_t size,
			uint32_t bn_bits, mpa_scratch_mem_sync_fn get,
			mpa_scratch_mem_sync_fn put,
			struct mpa_scratch_mem_sync *sync);

MPALIB_EXPORT void mpa_init_scratch_mem(mpa_scratch_mem pool, size_t size,
					uint32_t bn_bits);


/*
 * mpa_init_static
 * Initiate a mpanum to hold an integer of a certain size.
 * The parameter 'len' is the return value of the macro
 * mpa_StaticVarSizeInU32 called with the max bit size as parameter.
 *
 * \param src  The mpanum to be initialized
 * \param len  The allocated size in uint32_t of src
 */
MPALIB_EXPORT void mpa_init_static(mpanum src, uint32_t len);

MPALIB_EXPORT void mpa_init_static_fmm_context(mpa_fmm_context_base *context,
					       uint32_t len);

/*
 * From mpa_addsub.c
 */
MPALIB_EXPORT void mpa_add(mpanum dest, const mpanum op1, const mpanum op2,
			   mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_sub(mpanum dest, const mpanum op1, const mpanum op2,
			   mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_add_word(mpanum dest, const mpanum op1, mpa_word_t op2,
				mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_sub_word(mpanum dest, const mpanum op1, mpa_word_t op2,
				mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_neg(mpanum dest, const mpanum src);

/*
 * From mpa_mul.c
 */

MPALIB_EXPORT void mpa_mul(mpanum dest, const mpanum op1, const mpanum op2,
			   mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_mul_word(mpanum dest, const mpanum op1, mpa_word_t op2,
				mpa_scratch_mem pool);

/*
 * From mpa_div.c
 */

MPALIB_EXPORT void mpa_div(mpanum q, mpanum r,
			   const mpanum op1, const mpanum op2,
			   mpa_scratch_mem pool);

/*
 * From mpa_modulus.c
 */

MPALIB_EXPORT void mpa_mod(mpanum dest, const mpanum op, const mpanum n,
			   mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_add_mod(mpanum dest, const mpanum op1, const mpanum op2,
			       const mpanum n, mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_sub_mod(mpanum dest, const mpanum op1, const mpanum op2,
			       const mpanum n, mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_mul_mod(mpanum dest, const mpanum op1, const mpanum op2,
			       const mpanum n, mpa_scratch_mem pool);

MPALIB_EXPORT int mpa_inv_mod(mpanum dest, const mpanum op, const mpanum n,
			      mpa_scratch_mem pool);

/*
 * From mpa_cmp.c
 */

MPALIB_EXPORT int32_t mpa_cmp(const mpanum op1, const mpanum op2);

MPALIB_EXPORT int32_t mpa_cmp_short(const mpanum op1, int32_t op2);

/*
 * From mpa_conv.c
 */

MPALIB_EXPORT void mpa_set_S32(mpanum dest, int32_t short_val);

MPALIB_EXPORT int32_t mpa_get_S32(int32_t *dest, mpanum src);

MPALIB_EXPORT void mpa_set_word(mpanum dest, mpa_word_t src);

MPALIB_EXPORT mpa_word_t mpa_get_word(mpanum src);

/*
 * From mpa_shift.c
 */

MPALIB_EXPORT void mpa_shift_left(mpanum dest, const mpanum src,
				  mpa_word_t steps);

MPALIB_EXPORT void mpa_shift_right(mpanum dest, const mpanum src,
				   mpa_word_t steps);

/*
 * From mpa_gcd.c
 */
MPALIB_EXPORT void mpa_gcd(mpanum dest, const mpanum src1, const mpanum src2,
			   mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_extended_gcd(mpanum gcd, mpanum dest1, mpanum dest2,
				    const mpanum src1, const mpanum src2,
				    mpa_scratch_mem pool);

/*
 * From mpa_io.c
 */
MPALIB_EXPORT int mpa_get_str_size(void);

MPALIB_EXPORT int mpa_set_str(mpanum dest, const char *digitstr);

MPALIB_EXPORT char *mpa_get_str(char *str, int mode, const mpanum n);

MPALIB_EXPORT int mpa_set_oct_str(mpanum dest, const uint8_t *buffer,
				  size_t buffer_len, bool negative);

MPALIB_EXPORT int mpa_get_oct_str(uint8_t *buffer, size_t *buffer_len,
				  const mpanum n);

/*
 * From mpa_expmod.c
 */
MPALIB_EXPORT void mpa_exp_mod(mpanum dest, const mpanum op1, const mpanum op2,
			       const mpanum n, const mpanum r_modn,
			       const mpanum r2_modn, const mpa_word_t n_inv,
			       mpa_scratch_mem pool);

/*
 * From mpa_misc.c
 */

MPALIB_EXPORT void mpa_wipe(mpanum src);

MPALIB_EXPORT void mpa_copy(mpanum dest, const mpanum src);

MPALIB_EXPORT void mpa_abs(mpanum dest, const mpanum src);

MPALIB_EXPORT int mpa_highest_bit_index(const mpanum src);

MPALIB_EXPORT uint32_t mpa_get_bit(const mpanum src, uint32_t idx);

MPALIB_EXPORT int mpa_can_hold(mpanum dest, const mpanum src);

MPALIB_EXPORT int mpa_parity(const mpanum src);

MPALIB_EXPORT mpanum mpa_constant_one(void);

/*
 * From mpa_Random.c
 */

typedef uint32_t (*random_generator_cb)(void *buf, size_t blen);

MPALIB_EXPORT void mpa_set_random_generator(random_generator_cb callback);

MPALIB_EXPORT void mpa_get_random(mpanum dest, mpanum limit);

/*
 * From mpa_montgomery.c
 */
MPALIB_EXPORT int mpa_compute_fmm_context(const mpanum modulus, mpanum r_modn,
					  mpanum r2_modn, mpa_word_t *n_inv,
					  mpa_scratch_mem pool);

MPALIB_EXPORT void mpa_montgomery_mul(mpanum dest, mpanum op1, mpanum op2,
				      mpanum n, mpa_word_t n_inv,
				      mpa_scratch_mem pool);

/*
 * From mpa_mem_static.c
 */
MPALIB_EXPORT mpanum mpa_alloc_static_temp_var(mpanum *var,
					       mpa_scratch_mem pool);
MPALIB_EXPORT mpanum mpa_alloc_static_temp_var_size(int size_bits,
						    mpanum *var,
						    mpa_scratch_mem pool);
MPALIB_EXPORT void mpa_free_static_temp_var(mpanum *var, mpa_scratch_mem pool);

/*
 * From mpa_primetest.c
 */
MPALIB_EXPORT int mpa_is_prob_prime(mpanum n, int conf_level,
				    mpa_scratch_mem pool);

#endif /* include guard */
