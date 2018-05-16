// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include "mpa.h"

#define swp(a, b) do { \
		mpanum *tmp = *a; \
		*a = *b; \
		*b = tmp; \
	} while (0)

/*------------------------------------------------------------
 *
 *  mpa_exp_mod
 *
 *  Calculates dest = op1 ^ op2 mod n
 *
 * This function uses the Montgomery ladder concept as proposed by Marc Joye and
 * Sun-Ming Yen, which makes the function more resistant to timing attacks.
 */
void mpa_exp_mod(mpanum dest,
		 const mpanum op1,
		 const mpanum op2,
		 const mpanum n,
		 const mpanum r_modn,
		 const mpanum r2_modn,
		 const mpa_word_t n_inv, mpa_scratch_mem pool)
{
	mpanum A;
	mpanum tmp_a;
	mpanum xtilde;
	mpanum tmp_xtilde;
	mpanum *ptr_a;
	mpanum *ptr_tmp_a;
	mpanum *ptr_xtilde;
	mpanum *ptr_tmp_xtilde;
	int idx;

	mpa_alloc_static_temp_var(&A, pool);
	mpa_alloc_static_temp_var(&tmp_a, pool);
	mpa_alloc_static_temp_var(&xtilde, pool);
	mpa_alloc_static_temp_var(&tmp_xtilde, pool);

	/*
	 * Transform the base (op1) into Montgomery space. Use internal version
	 * since xtilde is big enough.
	 */
	__mpa_montgomery_mul(xtilde, op1, r2_modn, n, n_inv);

	mpa_copy(A, r_modn);

	ptr_a = &A;
	ptr_tmp_a = &tmp_a;
	ptr_xtilde = &xtilde;
	ptr_tmp_xtilde = &tmp_xtilde;

	__mpa_set_unused_digits_to_zero(A);
	__mpa_set_unused_digits_to_zero(xtilde);

	for (idx = mpa_highest_bit_index(op2); idx >= 0; idx--) {
		if (mpa_get_bit(op2, idx) == 0) {
			/* x' = A*x' */
			__mpa_montgomery_mul(*ptr_tmp_xtilde, *ptr_a,
					     *ptr_xtilde, n, n_inv);

			/* A = A^2 */
			__mpa_montgomery_mul(*ptr_tmp_a, *ptr_a, *ptr_a, n,
					     n_inv);
		} else {
			/* A = A*x' */
			__mpa_montgomery_mul(*ptr_tmp_a, *ptr_a, *ptr_xtilde, n,
					     n_inv);

			/* x' = x'^2 */
			__mpa_montgomery_mul(*ptr_tmp_xtilde, *ptr_xtilde,
					     *ptr_xtilde, n, n_inv);
		}

		/*
		 * The simple reason for swapping here is to avoid copy
		 * intermediate results, instead we're just moving the pointers.
		 */
		swp(&ptr_tmp_a, &ptr_a);
		swp(&ptr_tmp_xtilde, &ptr_xtilde);
	}

	/* Transform back from Montgomery space */
	__mpa_montgomery_mul(*ptr_tmp_a, (const mpanum)&const_one, *ptr_a,
			     n, n_inv);

	mpa_copy(dest, *ptr_tmp_a);

	mpa_free_static_temp_var(&A, pool);
	mpa_free_static_temp_var(&tmp_a, pool);
	mpa_free_static_temp_var(&xtilde, pool);
	mpa_free_static_temp_var(&tmp_xtilde, pool);
}
