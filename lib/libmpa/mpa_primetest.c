// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"

#define USE_PRIME_TABLE

#if defined(USE_PRIME_TABLE)
#include "mpa_primetable.h"
#endif

#define DEF_COMPOSITE   0
#define DEF_PRIME       1
#define PROB_PRIME     -1

/* Product of all primes < 1000 */
static const mpa_num_base const_small_prime_factors = {
	44,
	44,
	{0x2ED42696, 0x2BBFA177, 0x4820594F, 0xF73F4841,
	 0xBFAC313A, 0xCAC3EB81, 0xF6F26BF8, 0x7FAB5061,
	 0x59746FB7, 0xF71377F6, 0x3B19855B, 0xCBD03132,
	 0xBB92EF1B, 0x3AC3152C, 0xE87C8273, 0xC0AE0E69,
	 0x74A9E295, 0x448CCE86, 0x63CA1907, 0x8A0BF944,
	 0xF8CC3BE0, 0xC26F0AF5, 0xC501C02F, 0x6579441A,
	 0xD1099CDA, 0x6BC76A00, 0xC81A3228, 0xBFB1AB25,
	 0x70FA3841, 0x51B3D076, 0xCC2359ED, 0xD9EE0769,
	 0x75E47AF0, 0xD45FF31E, 0x52CCE4F6, 0x04DBC891,
	 0x96658ED2, 0x1753EFE5, 0x3AE4A5A6, 0x8FD4A97F,
	 0x8B15E7EB, 0x0243C3E1, 0xE0F0C31D, 0x0000000B}
};

/*
 * If n is less than this number (341550071728321 decimal) the Miller-Rabin
 * test (using specific bases) constitutes a primality proof.
 */
static const mpa_num_base const_miller_rabin_proof_limit = {
	2,
	2,
	{0x52B2C8C1, 0x000136A3}
};

static const mpa_num_base const_two = {
	1,
	1,
	{0x00000002}
};

/* foward declarations */
static int is_small_prime(mpanum n);
static int has_small_factors(mpanum n, mpa_scratch_mem pool);
static int primality_test_miller_rabin(mpanum n, int conf_level,
				      mpa_scratch_mem pool);

/*------------------------------------------------------------
 *
 *  mpa_is_prob_prime
 *
 * Returns:
 *   0 if n is definitely composite
 *   1 if n is definitely prime
 *  -1 if n is composite with a probability less than 2^(-conf_level)
 *
 */
int mpa_is_prob_prime(mpanum n, int conf_level, mpa_scratch_mem pool)
{
	int result = 0;

	/* Check if it's a small prime */
	result = is_small_prime(n);
	if (result != PROB_PRIME)
		goto cleanup;

	/* Test if n is divisible by any prime < 1000 */
	if (has_small_factors(n, pool)) {
		result = DEF_COMPOSITE;
		goto cleanup;
	}
	/* Check with Miller Rabin */
	result = primality_test_miller_rabin(n, conf_level, pool);

cleanup:
	return result;
}

#if defined(USE_PRIME_TABLE)
/*------------------------------------------------------------
 *
 *  check_table
 *
 */
static uint32_t check_table(uint32_t v)
{
	return (PRIME_TABLE[v >> 5] >> (v & 0x1f)) & 1;
}
#endif

/*------------------------------------------------------------
 *
 *  is_small_prime
 *
 *  Returns 1 if n is prime,
    Returns 0 if n is composite
 *  Returns -1 if we cannot decide
 *
 */
static int is_small_prime(mpanum n)
{
	mpa_word_t v;

	/* If n is larger than a mpa_word_t, we can only decide if */
	/* n is even. If it's odd we cannot tell. */
	if (__mpanum_size(n) > 1)
		return ((mpa_parity(n) == MPA_EVEN_PARITY) ? 0 : -1);

	v = mpa_get_word(n);	/* will convert negative n:s to positive v:s. */
	if ((v | 1) == 1)	/* 0 and 1 are not prime */
		return DEF_COMPOSITE;
	if (v == 2)		/* 2 is prime */
		return DEF_PRIME;
	if ((v & 1) == 0)
		return DEF_COMPOSITE;	/* but no other even number */

#if defined(USE_PRIME_TABLE)
	if (mpa_cmp_short(n, MAX_TABULATED_PRIME) > 0)
		return -1;
	v = (v - 3) >> 1;
	return check_table(v);
#else
	return -1;
#endif
}

/*------------------------------------------------------------
 *
 *  has_small_factors
 *
 *  returns 1 if n has small factors
 *  returns 0 if not.
 */
static int has_small_factors(mpanum n, mpa_scratch_mem pool)
{
	const mpa_num_base *factors = &const_small_prime_factors;
	int result;
	mpanum res;

	mpa_alloc_static_temp_var(&res, pool);
	mpa_gcd(res, n, (const mpanum)factors, pool);
	result = (mpa_cmp_short(res, 1) == 0) ? 0 : 1;
	mpa_free_static_temp_var(&res, pool);

	return result;
}

/*------------------------------------------------------------
 *
 *  primality_test_miller_rabin
 *
 */
static int primality_test_miller_rabin(mpanum n, int conf_level,
				      mpa_scratch_mem pool)
{
	int result;
	bool proof_version;
	static const int32_t proof_a[7] = { 2, 3, 5, 7, 11, 13, 17 };
	int cnt;
	int idx;
	int t;
	int e = 0;
	int cmp_one;
	mpanum a;
	mpanum q;
	mpanum n_minus_1;
	mpanum b;
	mpanum r_modn;
	mpanum r2_modn;
	mpa_word_t n_inv;

	mpa_alloc_static_temp_var(&r_modn, pool);
	mpa_alloc_static_temp_var(&r2_modn, pool);

	if (mpa_compute_fmm_context(n, r_modn, r2_modn, &n_inv, pool) == -1) {
		result = DEF_COMPOSITE;
		goto cleanup_short;
	}

	mpa_alloc_static_temp_var(&a, pool);
	mpa_alloc_static_temp_var(&q, pool);
	mpa_alloc_static_temp_var(&n_minus_1, pool);
	mpa_alloc_static_temp_var(&b, pool);

	proof_version =
	    (mpa_cmp(n, (mpanum) &const_miller_rabin_proof_limit) < 0);

	if (proof_version)
		cnt = 7;
	else	/* MR has 1/4 chance in failing a composite */
		cnt = (conf_level + 1) / 2;

	mpa_sub_word(n_minus_1, n, 1, pool);
	mpa_set(q, n_minus_1);
	t = 0;
	/* calculate q such that n - 1 = 2^t * q where q is odd */
	while (mpa_is_even(q)) {
		mpa_shift_right(q, q, 1);
		t++;
	}

	result = PROB_PRIME;
	for (idx = 0; idx < cnt && result == PROB_PRIME; idx++) {
		if (proof_version) {
			mpa_set_S32(a, proof_a[idx]);
			if (mpa_cmp(n, a) == 0) {
				result = DEF_PRIME;
				continue;
			}
		} else {
			/*
			 * Get random a, 1 < a < N by
			 * asking for a random in range 0 <= x < N - 2
			 * and then add 2 to it.
			 */
			mpa_sub_word(n_minus_1, n_minus_1, 1, pool);
			/* n_minus_1 is now N - 2 ! */
			mpa_get_random(a, n_minus_1);
			mpa_add_word(n_minus_1, n_minus_1, 1, pool);
			/* and a is now 2 <= a < N */
			mpa_add_word(a, a, 2, pool);
		}

		mpa_exp_mod(b, a, q, n, r_modn, r2_modn, n_inv, pool);
		e = 0;

inner_loop:
		cmp_one = mpa_cmp_short(b, 1);
		if ((cmp_one == 0) && (e > 0)) {
			result = DEF_COMPOSITE;
			continue;
		}

		if ((mpa_cmp(b, n_minus_1) == 0) ||
		    ((cmp_one == 0) && (e == 0))) {
			/* probably prime, try another a */
			continue;
		}

		e++;
		if (e < t) {
			mpa_exp_mod(b, b, (mpanum) &const_two, n, r_modn,
				    r2_modn, n_inv, pool);
			goto inner_loop;
		}
		result = DEF_COMPOSITE;
	}

	if (result == PROB_PRIME && proof_version)
		result = DEF_PRIME;

	mpa_free_static_temp_var(&a, pool);
	mpa_free_static_temp_var(&q, pool);
	mpa_free_static_temp_var(&n_minus_1, pool);
	mpa_free_static_temp_var(&b, pool);
cleanup_short:
	mpa_free_static_temp_var(&r_modn, pool);
	mpa_free_static_temp_var(&r2_modn, pool);

	return result;
}
