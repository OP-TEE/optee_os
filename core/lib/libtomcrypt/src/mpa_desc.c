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

#include "tomcrypt_mpa.h"
#include <mpa.h>

static mpa_scratch_mem external_pool;
static void (*get_external_pool)(void);
static void (*put_external_pool)(void);

void init_mpa_tomcrypt(mpa_scratch_mem pool, void (*get_pool)(void),
			void (*put_pool)(void))
{
	external_pool = pool;
	get_external_pool = get_pool;
	put_external_pool = put_pool;
}


static int init(void **a)
{
	LTC_ARGCHK(a != NULL);
	get_external_pool();
	if (!mpa_alloc_static_temp_var((mpanum *)a, external_pool)) {
		put_external_pool();
		return CRYPT_MEM;
	}
	mpa_set_S32(*a, 0);
	return CRYPT_OK;
}

static int init_size(int size_bits, void **a)
{
	LTC_ARGCHK(a != NULL);
	get_external_pool();
	if (!mpa_alloc_static_temp_var_size(size_bits, (mpanum *)a,
					    external_pool)) {
		put_external_pool();
		return CRYPT_MEM;
	}
	mpa_set_S32(*a, 0);
	return CRYPT_OK;
}

static void deinit(void *a)
{
	LTC_ARGCHKVD(a != NULL);

	mpa_free_static_temp_var((mpanum *) &a, external_pool);
	put_external_pool();
}

static int neg(void *a, void *b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	mpa_neg((mpanum)b, (const mpanum)a);
	return CRYPT_OK;
}

static int copy(void *a, void *b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	mpa_copy((mpanum)b, (const mpanum)a);
	return CRYPT_OK;
}

static int init_copy(void **a, void *b)
{
	if (init(a) != CRYPT_OK) {
		return CRYPT_MEM;
	}
	return copy(b, *a);
}

/* ---- trivial ---- */
static int set_int(void *a, unsigned long b)
{
	LTC_ARGCHK(a != NULL);
	if (b > (unsigned long) UINT32_MAX) {
		return CRYPT_INVALID_ARG;
	}
	mpa_set_word((mpanum) a, (mpa_word_t)b);
	return CRYPT_OK;
}

static unsigned long get_int(void *a)
{
	LTC_ARGCHK(a != NULL);
	return mpa_get_word((mpanum)a);
}

static unsigned long get_digit(void *a, int n)
{
	LTC_ARGCHK(a != NULL);
	return __mpanum_get_word(n, (mpanum) a);
}

static int get_digit_count(void *a)
{
	LTC_ARGCHK(a != NULL);
	return __mpanum_size((mpanum) a);
}

static int compare(void *a, void *b)
{
	int ret;
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	ret = mpa_cmp((const mpanum)a, (const mpanum)b);
	if (ret < 0) {
		return LTC_MP_LT;
	} else if (ret > 0) {
		return LTC_MP_GT;
	} else {
		return LTC_MP_EQ;
	}
}

static int compare_d(void *a, unsigned long b)
{
	int ret;
	LTC_ARGCHK(a != NULL);
	// this particular case must be handled separately...
	if (b > (unsigned long) MPA_INT_MAX) {
		mpanum tmp = (mpanum) a;
		ret = (tmp->size <= 0 ? LTC_MP_LT :
				tmp->size > 1  ? LTC_MP_GT :
						tmp->d[0] < b  ? LTC_MP_LT :
								tmp->d[0] == b ? LTC_MP_EQ : LTC_MP_GT);
	} else {
		ret = mpa_cmp_short(((const mpanum)a), b);
	}
	if (ret < 0) {
		return LTC_MP_LT;
	} else if (ret > 0) {
		return LTC_MP_GT;
	} else {
		return LTC_MP_EQ;
	}
}

static int count_bits(void *a)
{
	LTC_ARGCHK(a != NULL);
	// mpa_highest_bit_index returns the index of the highest '1' bit starting at 0
	// so adding 1 to the result gives the wanted result
	return mpa_highest_bit_index((const mpanum)a) + 1;
}

static int count_lsb_bits(void *a)
{
	LTC_ARGCHK(a != NULL);
	if (((mpanum)a)->size == 0) {
		return 0;
	}
	int zero_limb_nbr = 0;
	int zero_bit_nbr = 0;
	const mpanum aa = (mpanum) a;
	while (aa->d[zero_limb_nbr] == 0) {
		++zero_limb_nbr;
	}
	zero_bit_nbr = zero_limb_nbr * MPA_WORD_SIZE;
	while (!mpa_get_bit(aa, zero_bit_nbr)) {
		++zero_bit_nbr;
	}

	return zero_bit_nbr;
}


static int twoexpt(void *a, int n)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(n >= 0);
	int i;
	mpa_asize_t q; /* quotient of n div WORD_SIZE */
	mpa_asize_t r; /* remainder of n div WORD_SIZE */

	r = n & (MPA_WORD_SIZE - 1);    /* 0 <= r < WORD_SIZE */
	q = n >> MPA_LOG_OF_WORD_SIZE;  /* 0 <= q */

	if (((mpanum)a)->alloc < (q + 1)) {
		return CRYPT_MEM;
	}
	((mpanum)a)->size = q + 1;
	for (i = 0; i < ((mpanum)a)->size; ++i) {
		((mpanum)a)->d[i] = 0;
	}
	((mpanum)a)->d[q] = 1 << r;
	return CRYPT_OK;
}

/* ---- conversions ---- */

/* read ascii string */
static int read_radix(void *a, const char *b, int radix)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	if (radix != 16) {
		return CRYPT_ERROR;
	}
	mpa_set_str((mpanum)a, b);
	return CRYPT_OK;
}

/* write one */
static int write_radix(void *a, char *b, int radix)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	if (mpa_get_str(b, MPA_STRING_MODE_HEX_UC, (const mpanum)a) == 0) {
		return CRYPT_MEM;
	}
	return CRYPT_OK;
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
	unsigned long t;
	LTC_ARGCHK(a != NULL);
	t = count_bits(a);
	if (mpa_cmp_short((const mpanum)a, 0) == 0) return 0;
	return (t>>3) + ((t&7)?1:0);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	size_t len = unsigned_size(a);
	mpa_get_oct_str(b, &len, (const mpanum) a);
	return CRYPT_OK;
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	mpa_set_oct_str((mpanum) a, b, len, 0);
	return CRYPT_OK;
}

/* add */
static int add(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	get_external_pool();
	mpa_add(c, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

static int addi(void *a, unsigned long b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(c != NULL);
	if (b > (unsigned long) UINT32_MAX) {
		return CRYPT_INVALID_ARG;
	}
	get_external_pool();
	mpa_add_word(c, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

/* sub */
static int sub(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	get_external_pool();
	mpa_sub(c, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

static int subi(void *a, unsigned long b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(c != NULL);
	if (b > (unsigned long) UINT32_MAX) {
		return CRYPT_INVALID_ARG;
	}
	get_external_pool();
	mpa_sub_word(c, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

/* mul */
static int mul(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	get_external_pool();
	mpa_mul(c, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

static int muli(void *a, unsigned long b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(c != NULL);
	if (b > (unsigned long) UINT32_MAX) {
		return CRYPT_INVALID_ARG;
	}
	get_external_pool();
	mpa_mul_word(c, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

/* sqr */
static int sqr(void *a, void *b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	get_external_pool();
	mpa_mul(b, a, a, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	get_external_pool();
	mpa_div(c, d, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

static int div_2(void *a, void *b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	mpa_shift_right(b, a, 1);
	return CRYPT_OK;
}

/* modi */
static int modi(void *a, unsigned long b, unsigned long *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(c != NULL);
	if (b > (unsigned long) UINT32_MAX) {
		return CRYPT_INVALID_ARG;
	}
	int err;
	void *tmp;
	if ((err = init(&tmp)) != CRYPT_OK) {
		return CRYPT_MEM;
	}

	if (set_int(tmp, b) != CRYPT_OK) {goto err;}
	if (divide(a, tmp, NULL, tmp) != CRYPT_OK) {goto err;}

	*c = get_int(tmp);

	err:
	deinit(tmp);
	return CRYPT_OK;
}

/* gcd */
static int gcd(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	get_external_pool();
	mpa_gcd(c, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	void *tmp;
	if (init(&tmp) != CRYPT_OK) {
		return CRYPT_MEM;
	}

	if (mul(a, b, tmp) != CRYPT_OK) {goto err;}
	if (gcd(a, b, c) != CRYPT_OK) {goto err;}

	/* We use the following equality: gcd(a, b) * lcm(a, b) = a * b */
	if (divide(tmp, c, c, NULL) != CRYPT_OK) {goto err;}
	err:
	deinit(tmp);
	return CRYPT_OK;
}

static int mod(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	get_external_pool();
	mpa_mod(c, a, b, external_pool);
	if (mpa_cmp_short(c, 0) < 0) {
		mpa_add(c, c, b, external_pool);
	}
	put_external_pool();
	return CRYPT_OK;
}

static int mulmod(void *a, void *b, void *c, void *d)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	LTC_ARGCHK(d != NULL);
	void *tmpa, *tmpb;

	mp_init_multi(&tmpa, &tmpb, NULL);

	mod(a, c, tmpa);
	mod(b, c, tmpb);
	get_external_pool();
	mpa_mul_mod(d, tmpa, tmpb, c, external_pool);
	put_external_pool();
	mp_clear_multi(tmpa, tmpb, NULL);
	return CRYPT_OK;
}

static int sqrmod(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	return mulmod(a, a, b, c);
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	LTC_ARGCHK(b != c);
	mod(a, b, c);
	get_external_pool();
	if (mpa_inv_mod(c, c, b, external_pool) != 0) {
		put_external_pool();
		return CRYPT_ERROR;
	}
	put_external_pool();

	return CRYPT_OK;
}

/* setup */
static int montgomery_setup(void *a, void **b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	mpa_word_t len = mpa_fmm_context_size_in_U32(count_bits(a));
	*b = malloc(len * sizeof(mpa_word_t));
	if (*b == NULL) {
		return CRYPT_MEM;
	}
	mpa_fmm_context_base * b_tmp = (mpa_fmm_context_base *) *b;
	mpa_init_static_fmm_context(b_tmp, len);
	get_external_pool();
	mpa_compute_fmm_context(a, b_tmp->r_ptr, b_tmp->r2_ptr, &b_tmp->n_inv,
				external_pool);
	put_external_pool();
	return CRYPT_OK;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	mpa_asize_t s;
	s = __mpanum_size((mpanum) b);
	twoexpt(a, s * MPA_WORD_SIZE);
	get_external_pool();
	mpa_mod(a, a, b, external_pool);
	put_external_pool();
	return CRYPT_OK;
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	mpanum tmp;

	get_external_pool();
	init((void **)&tmp);
	// WARNING
	//  Workaround for a bug when a > b (a greater than the modulus)
	if (compare(a, b) == LTC_MP_GT) {
		mpa_mod(a, a, b, external_pool);
	}
	mpa_montgomery_mul(tmp, a, mpa_constant_one(), b,
			   ((mpa_fmm_context)c)->n_inv, external_pool);
	mpa_copy(a, tmp);
	deinit(tmp);
	put_external_pool();
	return CRYPT_OK;
}

/* clean up */
static void montgomery_deinit(void *a)
{
	free(a);
}

static int exptmod(void *a, void *b, void *c, void *d)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	LTC_ARGCHK(c != NULL);
	LTC_ARGCHK(d != NULL);
	void *c_mont;
	void *d_tmp;
	int memguard;

	montgomery_setup(c, &c_mont);

	memguard = (a == d || b == d);

	if (memguard) {
		init(&d_tmp);
	} else {
		d_tmp = d;
	}

	// WARNING !!
	// Temporary fix, since ExpMod behaves badly when a > c
	//           (ie "a" is greater than the modulus)
	mod(a, c, d_tmp);


	get_external_pool();
	mpa_exp_mod(d, d_tmp, b, c, ((mpa_fmm_context)c_mont)->r_ptr,
		   ((mpa_fmm_context)c_mont)->r2_ptr,
		   ((mpa_fmm_context)c_mont)->n_inv, external_pool);
	put_external_pool();
	montgomery_deinit(c_mont);
	if (memguard) {
		deinit(d_tmp);
	}
	return CRYPT_OK;
}

static int isprime(void *a, int *b)
{
	LTC_ARGCHK(a != NULL);
	LTC_ARGCHK(b != NULL);
	get_external_pool();
	*b = mpa_is_prob_prime(a, 100, external_pool) != 0 ?
		LTC_MP_YES : LTC_MP_NO;
	put_external_pool();
	return CRYPT_OK;
}

ltc_math_descriptor ltc_mp = {
	.name = "MPA",
	.bits_per_digit = MPA_WORD_SIZE,

	.init = &init,
	.init_size = &init_size,
	.init_copy = &init_copy,
	.deinit = &deinit,

	.neg = &neg,
	.copy = &copy,

	.set_int = &set_int,
	.get_int = &get_int,
	.get_digit = &get_digit,
	.get_digit_count = &get_digit_count,
	.compare = &compare,
	.compare_d = &compare_d,
	.count_bits = &count_bits,
	.count_lsb_bits = &count_lsb_bits,
	.twoexpt = &twoexpt,

	.read_radix = &read_radix,
	.write_radix = &write_radix,
	.unsigned_size = &unsigned_size,
	.unsigned_write = &unsigned_write,
	.unsigned_read = &unsigned_read,

	.add = &add,
	.addi = &addi,
	.sub = &sub,
	.subi = &subi,
	.mul = &mul,
	.muli = &muli,
	.sqr = &sqr,
	.mpdiv = &divide,
	.div_2 = &div_2,
	.modi = &modi,
	.gcd = &gcd,
	.lcm = &lcm,

	.mod = &mod,
	.mulmod = &mulmod,
	.sqrmod = &sqrmod,
	.invmod = &invmod,

	.montgomery_setup = &montgomery_setup,
	.montgomery_normalization = &montgomery_normalization,
	.montgomery_reduce = &montgomery_reduce,
	.montgomery_deinit = &montgomery_deinit,

	.exptmod = &exptmod,
	.isprime = &isprime,

#ifdef LTC_MECC
#ifdef LTC_MECC_FP
	.ecc_ptmul = &ltc_ecc_fp_mulmod,
#else
	.ecc_ptmul = &ltc_ecc_mulmod,
#endif /* LTC_MECC_FP */
	.ecc_ptadd = &ltc_ecc_projective_add_point,
	.ecc_ptdbl = &ltc_ecc_projective_dbl_point,
	.ecc_map = &ltc_ecc_map,
#ifdef LTC_ECC_SHAMIR
#ifdef LTC_MECC_FP
	.ecc_mul2add = &ltc_ecc_fp_mul2add,
#else
	.ecc_mul2add = &ltc_ecc_mul2add,
#endif /* LTC_MECC_FP */
#endif /* LTC_ECC_SHAMIR */
#endif /* LTC_MECC */

#ifdef LTC_MRSA
	.rsa_keygen = &rsa_make_key,
	.rsa_me = &rsa_exptmod,
#endif

};
