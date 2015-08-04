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
#include "mpa.h"

/*------------------------------------------------------------
 *
 *  mpa_exp_mod
 *
 *  Calculates dest = op1 ^ op2 mod n
 *
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
	mpanum B;
	mpanum xtilde;
	mpanum *ptr_a;
	mpanum *ptr_b;
	mpanum *swapper;
	int idx;

	mpa_alloc_static_temp_var(&A, pool);
	mpa_alloc_static_temp_var(&B, pool);
	mpa_alloc_static_temp_var(&xtilde, pool);

	/* transform to Montgomery space */
	/* use internal version since xtidle is big enough */
	__mpa_montgomery_mul(xtilde, op1, r2_modn, n, n_inv);

	mpa_copy(A, r_modn);
	ptr_a = &A;
	ptr_b = &B;
	__mpa_set_unused_digits_to_zero(A);
	__mpa_set_unused_digits_to_zero(B);
	for (idx = mpa_highest_bit_index(op2); idx >= 0; idx--) {
		__mpa_montgomery_mul(*ptr_b, *ptr_a, *ptr_a, n, n_inv);
		if (mpa_get_bit(op2, idx) == 1) {
			__mpa_montgomery_mul(*ptr_a, *ptr_b, xtilde, n, n_inv);
		} else {
			swapper = ptr_a;
			ptr_a = ptr_b;
			ptr_b = swapper;
		}
	}

	/* transform back form Montgomery space */
	__mpa_montgomery_mul(*ptr_b, (const mpanum)&const_one, *ptr_a,
			     n, n_inv);

	mpa_copy(dest, *ptr_b);

	mpa_free_static_temp_var(&A, pool);
	mpa_free_static_temp_var(&B, pool);
	mpa_free_static_temp_var(&xtilde, pool);
}
