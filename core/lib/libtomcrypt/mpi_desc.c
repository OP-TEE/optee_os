// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <crypto/crypto.h>
#include <kernel/panic.h>
#include <mbedtls/bignum.h>
#include <mempool.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt_private.h>
#include <tomcrypt_mp.h>
#include <util.h>

#if defined(_CFG_CORE_LTC_PAGER)
#include <mm/core_mmu.h>
#include <mm/tee_pager.h>
#endif

/* Size needed for xtest to pass reliably on both ARM32 and ARM64 */
#define MPI_MEMPOOL_SIZE	(46 * 1024)

/* From mbedtls/library/bignum.c */
#define ciL		(sizeof(mbedtls_mpi_uint))	/* chars in limb  */
#define biL		(ciL << 3)			/* bits  in limb  */
#define BITS_TO_LIMBS(i)	((i) / biL + ((i) % biL != 0))

#if defined(_CFG_CORE_LTC_PAGER)
/* allocate pageable_zi vmem for mp scratch memory pool */
static struct mempool *get_mp_scratch_memory_pool(void)
{
	size_t size;
	void *data;

	size = ROUNDUP(MPI_MEMPOOL_SIZE, SMALL_PAGE_SIZE);
	data = tee_pager_alloc(size);
	if (!data)
		panic();

	return mempool_alloc_pool(data, size, tee_pager_release_phys);
}
#else /* _CFG_CORE_LTC_PAGER */
static struct mempool *get_mp_scratch_memory_pool(void)
{
	static uint8_t data[MPI_MEMPOOL_SIZE] __aligned(MEMPOOL_ALIGN);

	return mempool_alloc_pool(data, sizeof(data), NULL);
}
#endif

void init_mp_tomcrypt(void)
{
	struct mempool *p = get_mp_scratch_memory_pool();

	if (!p)
		panic();
	mbedtls_mpi_mempool = p;
	assert(!mempool_default);
	mempool_default = p;
}

static int init(void **a)
{
	mbedtls_mpi *bn = mempool_alloc(mbedtls_mpi_mempool, sizeof(*bn));

	if (!bn)
		return CRYPT_MEM;

	mbedtls_mpi_init_mempool(bn);
	*a = bn;
	return CRYPT_OK;
}

static int init_size(int size_bits __unused, void **a)
{
	return init(a);
}

static void deinit(void *a)
{
	mbedtls_mpi_free((mbedtls_mpi *)a);
	mempool_free(mbedtls_mpi_mempool, a);
}

static int neg(void *a, void *b)
{
	if (mbedtls_mpi_copy(b, a))
		return CRYPT_MEM;
	((mbedtls_mpi *)b)->s *= -1;
	return CRYPT_OK;
}

static int copy(void *a, void *b)
{
	if (mbedtls_mpi_copy(b, a))
		return CRYPT_MEM;
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
static int set_int(void *a, ltc_mp_digit b)
{
	uint32_t b32 = b;

	if (b32 != b)
		return CRYPT_INVALID_ARG;

	mbedtls_mpi_uint p = b32;
	mbedtls_mpi bn = { .s = 1, .n = 1, .p = &p };

	if (mbedtls_mpi_copy(a, &bn))
		return CRYPT_MEM;
	return CRYPT_OK;
}

static unsigned long get_int(void *a)
{
	mbedtls_mpi *bn = a;

	if (!bn->n)
		return 0;

	return bn->p[bn->n - 1];
}

static ltc_mp_digit get_digit(void *a, int n)
{
	mbedtls_mpi *bn = a;

	COMPILE_TIME_ASSERT(sizeof(ltc_mp_digit) >= sizeof(mbedtls_mpi_uint));

	if (n < 0 || (size_t)n >= bn->n)
		return 0;

	return bn->p[n];
}

static int get_digit_count(void *a)
{
	return ROUNDUP(mbedtls_mpi_size(a), sizeof(mbedtls_mpi_uint)) /
	       sizeof(mbedtls_mpi_uint);
}

static int compare(void *a, void *b)
{
	int ret = mbedtls_mpi_cmp_mpi(a, b);

	if (ret < 0)
		return LTC_MP_LT;

	if (ret > 0)
		return LTC_MP_GT;

	return LTC_MP_EQ;
}

static int compare_d(void *a, ltc_mp_digit b)
{
	unsigned long v = b;
	unsigned int shift = 31;
	uint32_t mask = BIT(shift) - 1;
	mbedtls_mpi bn;

	mbedtls_mpi_init_mempool(&bn);
	while (true) {
		mbedtls_mpi_add_int(&bn, &bn, v & mask);
		v >>= shift;
		if (!v)
			break;
		mbedtls_mpi_shift_l(&bn, shift);
	}

	int ret = compare(a, &bn);

	mbedtls_mpi_free(&bn);

	return ret;
}

static int count_bits(void *a)
{
	return mbedtls_mpi_bitlen(a);
}

static int count_lsb_bits(void *a)
{
	return mbedtls_mpi_lsb(a);
}


static int twoexpt(void *a, int n)
{
	if (mbedtls_mpi_set_bit(a, n, 1))
		return CRYPT_MEM;

	return CRYPT_OK;
}

/* ---- conversions ---- */

/* read ascii string */
static int read_radix(void *a, const char *b, int radix)
{
	int res = mbedtls_mpi_read_string(a, radix, b);

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;
	if (res)
		return CRYPT_ERROR;

	return CRYPT_OK;
}

/* write one */
static int write_radix(void *a, char *b, int radix)
{
	size_t ol = SIZE_MAX;
	int res = mbedtls_mpi_write_string(a, radix, b, ol, &ol);

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;
	if (res)
		return CRYPT_ERROR;

	return CRYPT_OK;
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
	return mbedtls_mpi_size(a);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
	int res = mbedtls_mpi_write_binary(a, b, unsigned_size(a));

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;
	if (res)
		return CRYPT_ERROR;

	return CRYPT_OK;
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
	int res = mbedtls_mpi_read_binary(a, b, len);

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;
	if (res)
		return CRYPT_ERROR;

	return CRYPT_OK;
}

/* add */
static int add(void *a, void *b, void *c)
{
	if (mbedtls_mpi_add_mpi(c, a, b))
		return CRYPT_MEM;

	return CRYPT_OK;
}

static int addi(void *a, ltc_mp_digit b, void *c)
{
	uint32_t b32 = b;

	if (b32 != b)
		return CRYPT_INVALID_ARG;

	mbedtls_mpi_uint p = b32;
	mbedtls_mpi bn = { .s = 1, .n = 1, .p = &p };

	return add(a, &bn, c);
}

/* sub */
static int sub(void *a, void *b, void *c)
{
	if (mbedtls_mpi_sub_mpi(c, a, b))
		return CRYPT_MEM;

	return CRYPT_OK;
}

static int subi(void *a, ltc_mp_digit b, void *c)
{
	uint32_t b32 = b;

	if (b32 != b)
		return CRYPT_INVALID_ARG;

	mbedtls_mpi_uint p = b32;
	mbedtls_mpi bn = { .s = 1, .n = 1, .p = &p };

	return sub(a, &bn, c);
}

/* mul */
static int mul(void *a, void *b, void *c)
{
	if (mbedtls_mpi_mul_mpi(c, a, b))
		return CRYPT_MEM;

	return CRYPT_OK;
}

static int muli(void *a, ltc_mp_digit b, void *c)
{
	if (b > (unsigned long) UINT32_MAX)
		return CRYPT_INVALID_ARG;

	if (mbedtls_mpi_mul_int(c, a, b))
		return CRYPT_MEM;

	return CRYPT_OK;
}

/* sqr */
static int sqr(void *a, void *b)
{
	return mul(a, a, b);
}

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
	int res = mbedtls_mpi_div_mpi(c, d, a, b);

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;
	if (res)
		return CRYPT_ERROR;

	return CRYPT_OK;
}

static int div_2(void *a, void *b)
{
	if (mbedtls_mpi_copy(b, a))
		return CRYPT_MEM;

	if (mbedtls_mpi_shift_r(b, 1))
		return CRYPT_MEM;

	return CRYPT_OK;
}

/* modi */
static int modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
	mbedtls_mpi bn_b;
	mbedtls_mpi bn_c;
	int res = 0;

	mbedtls_mpi_init_mempool(&bn_b);
	mbedtls_mpi_init_mempool(&bn_c);

	res = set_int(&bn_b, b);
	if (res)
		return res;

	res = mbedtls_mpi_mod_mpi(&bn_c, &bn_b, a);
	if (!res)
		*c = get_int(&bn_c);

	mbedtls_mpi_free(&bn_b);
	mbedtls_mpi_free(&bn_c);

	if (res)
		return CRYPT_MEM;

	return CRYPT_OK;
}

/* gcd */
static int gcd(void *a, void *b, void *c)
{
	if (mbedtls_mpi_gcd(c, a, b))
		return CRYPT_MEM;

	return CRYPT_OK;
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
	int res = CRYPT_MEM;
	mbedtls_mpi tmp;

	mbedtls_mpi_init_mempool(&tmp);
	if (mbedtls_mpi_mul_mpi(&tmp, a, b))
		goto out;

	if (mbedtls_mpi_gcd(c, a, b))
		goto out;

	/* We use the following equality: gcd(a, b) * lcm(a, b) = a * b */
	res = divide(&tmp, c, c, NULL);
out:
	mbedtls_mpi_free(&tmp);
	return res;
}

static int mod(void *a, void *b, void *c)
{
	int res = mbedtls_mpi_mod_mpi(c, a, b);

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;
	if (res)
		return CRYPT_ERROR;

	return CRYPT_OK;
}

static int addmod(void *a, void *b, void *c, void *d)
{
	int res = add(a, b, d);

	if (res)
		return res;

	return mod(d, c, d);
}

static int submod(void *a, void *b, void *c, void *d)
{
	int res = sub(a, b, d);

	if (res)
		return res;

	return mod(d, c, d);
}

static int mulmod(void *a, void *b, void *c, void *d)
{
	int res;
	mbedtls_mpi ta;
	mbedtls_mpi tb;

	mbedtls_mpi_init_mempool(&ta);
	mbedtls_mpi_init_mempool(&tb);

	res = mod(a, c, &ta);
	if (res)
		goto out;
	res = mod(b, c, &tb);
	if (res)
		goto out;
	res = mul(&ta, &tb, d);
	if (res)
		goto out;
	res = mod(d, c, d);
out:
	mbedtls_mpi_free(&ta);
	mbedtls_mpi_free(&tb);
	return res;
}

static int sqrmod(void *a, void *b, void *c)
{
	return mulmod(a, a, b, c);
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
	int res = mbedtls_mpi_inv_mod(c, a, b);

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;
	if (res)
		return CRYPT_ERROR;

	return CRYPT_OK;
}


/* setup */
static int montgomery_setup(void *a, void **b)
{
	*b = mempool_alloc(mbedtls_mpi_mempool, sizeof(mbedtls_mpi_uint));
	if (!*b)
		return CRYPT_MEM;

	mbedtls_mpi_montg_init(*b, a);

	return CRYPT_OK;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
	size_t c = ROUNDUP(mbedtls_mpi_size(b), sizeof(mbedtls_mpi_uint)) * 8;

	if (mbedtls_mpi_lset(a, 1))
		return CRYPT_MEM;
	if (mbedtls_mpi_shift_l(a, c))
		return CRYPT_MEM;
	if (mbedtls_mpi_mod_mpi(a, a, b))
		return CRYPT_MEM;

	return CRYPT_OK;
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
	mbedtls_mpi A;
	mbedtls_mpi *N = b;
	mbedtls_mpi_uint *mm = c;
	mbedtls_mpi T;
	int ret = CRYPT_MEM;

	mbedtls_mpi_init_mempool(&T);
	mbedtls_mpi_init_mempool(&A);

	if (mbedtls_mpi_grow(&T, (N->n + 1) * 2))
		goto out;

	if (mbedtls_mpi_cmp_mpi(a, N) > 0) {
		if (mbedtls_mpi_mod_mpi(&A, a, N))
			goto out;
	} else {
		if (mbedtls_mpi_copy(&A, a))
			goto out;
	}

	if (mbedtls_mpi_grow(&A, N->n + 1))
		goto out;

	mbedtls_mpi_montred(&A, N, *mm, &T);

	if (mbedtls_mpi_copy(a, &A))
		goto out;

	ret = CRYPT_OK;
out:
	mbedtls_mpi_free(&A);
	mbedtls_mpi_free(&T);

	return ret;
}

/* clean up */
static void montgomery_deinit(void *a)
{
	mempool_free(mbedtls_mpi_mempool, a);
}

/*
 * This function calculates:
 *  d = a^b mod c
 *
 * @a: base
 * @b: exponent
 * @c: modulus
 * @d: destination
 */
static int exptmod(void *a, void *b, void *c, void *d)
{
	int res;

	if (d == a || d == b || d == c) {
		mbedtls_mpi dest;

		mbedtls_mpi_init_mempool(&dest);
		res = mbedtls_mpi_exp_mod(&dest, a, b, c, NULL);
		if (!res)
			res = mbedtls_mpi_copy(d, &dest);
		mbedtls_mpi_free(&dest);
	} else {
		res = mbedtls_mpi_exp_mod(d, a, b, c, NULL);
	}

	if (res)
		return CRYPT_MEM;
	else
		return CRYPT_OK;
}

static int rng_read(void *ignored __unused, unsigned char *buf, size_t blen)
{
	if (crypto_rng_read(buf, blen))
		return MBEDTLS_ERR_MPI_FILE_IO_ERROR;
	return 0;
}

static int isprime(void *a, int b, int *c)
{
	int res = mbedtls_mpi_is_prime_ext(a, b, rng_read, NULL);

	if (res == MBEDTLS_ERR_MPI_ALLOC_FAILED)
		return CRYPT_MEM;

	if (res)
		*c = LTC_MP_NO;
	else
		*c = LTC_MP_YES;

	return CRYPT_OK;
}

static int mpi_rand(void *a, int size)
{
	if (mbedtls_mpi_fill_random(a, size, rng_read, NULL))
		return CRYPT_MEM;

	return CRYPT_OK;
}

ltc_math_descriptor ltc_mp = {
	.name = "MPI",
	.bits_per_digit = sizeof(mbedtls_mpi_uint) * 8,

	.init = init,
	.init_size = init_size,
	.init_copy = init_copy,
	.deinit = deinit,

	.neg = neg,
	.copy = copy,

	.set_int = set_int,
	.get_int = get_int,
	.get_digit = get_digit,
	.get_digit_count = get_digit_count,
	.compare = compare,
	.compare_d = compare_d,
	.count_bits = count_bits,
	.count_lsb_bits = count_lsb_bits,
	.twoexpt = twoexpt,

	.read_radix = read_radix,
	.write_radix = write_radix,
	.unsigned_size = unsigned_size,
	.unsigned_write = unsigned_write,
	.unsigned_read = unsigned_read,

	.add = add,
	.addi = addi,
	.sub = sub,
	.subi = subi,
	.mul = mul,
	.muli = muli,
	.sqr = sqr,
	.mpdiv = divide,
	.div_2 = div_2,
	.modi = modi,
	.gcd = gcd,
	.lcm = lcm,

	.mulmod = mulmod,
	.sqrmod = sqrmod,
	.invmod = invmod,

	.montgomery_setup = montgomery_setup,
	.montgomery_normalization = montgomery_normalization,
	.montgomery_reduce = montgomery_reduce,
	.montgomery_deinit = montgomery_deinit,

	.exptmod = exptmod,
	.isprime = isprime,

#ifdef LTC_MECC
#ifdef LTC_MECC_FP
	.ecc_ptmul = ltc_ecc_fp_mulmod,
#else
	.ecc_ptmul = ltc_ecc_mulmod,
#endif /* LTC_MECC_FP */
	.ecc_ptadd = ltc_ecc_projective_add_point,
	.ecc_ptdbl = ltc_ecc_projective_dbl_point,
	.ecc_map = ltc_ecc_map,
#ifdef LTC_ECC_SHAMIR
#ifdef LTC_MECC_FP
	.ecc_mul2add = ltc_ecc_fp_mul2add,
#else
	.ecc_mul2add = ltc_ecc_mul2add,
#endif /* LTC_MECC_FP */
#endif /* LTC_ECC_SHAMIR */
#endif /* LTC_MECC */

#ifdef LTC_MRSA
	.rsa_keygen = rsa_make_key,
	.rsa_me = rsa_exptmod,
#endif
	.addmod = addmod,
	.submod = submod,
	.rand = mpi_rand,

};

size_t crypto_bignum_num_bytes(struct bignum *a)
{
	return mbedtls_mpi_size((mbedtls_mpi *)a);
}

size_t crypto_bignum_num_bits(struct bignum *a)
{
	return mbedtls_mpi_bitlen((mbedtls_mpi *)a);
}

int32_t crypto_bignum_compare(struct bignum *a, struct bignum *b)
{
	return mbedtls_mpi_cmp_mpi((mbedtls_mpi *)a, (mbedtls_mpi *)b);
}

void crypto_bignum_bn2bin(const struct bignum *from, uint8_t *to)
{
	const mbedtls_mpi *f = (const mbedtls_mpi *)from;
	int rc __maybe_unused = 0;

	rc = mbedtls_mpi_write_binary(f, (void *)to, mbedtls_mpi_size(f));
	assert(!rc);
}

TEE_Result crypto_bignum_bin2bn(const uint8_t *from, size_t fromsize,
			 struct bignum *to)
{
	if (mbedtls_mpi_read_binary((mbedtls_mpi *)to, (const void *)from,
				    fromsize))
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

void crypto_bignum_copy(struct bignum *to, const struct bignum *from)
{
	int rc __maybe_unused = 0;

	rc = mbedtls_mpi_copy((mbedtls_mpi *)to, (const mbedtls_mpi *)from);
	assert(!rc);
}

struct bignum *crypto_bignum_allocate(size_t size_bits)
{
	mbedtls_mpi *bn = malloc(sizeof(*bn));

	if (!bn)
		return NULL;

	mbedtls_mpi_init(bn);
	if (mbedtls_mpi_grow(bn, BITS_TO_LIMBS(size_bits))) {
		free(bn);
		return NULL;
	}

	return (struct bignum *)bn;
}

void crypto_bignum_free(struct bignum **s)
{
	assert(s);

	mbedtls_mpi_free((mbedtls_mpi *)*s);
	free(*s);
	*s = NULL;
}

void crypto_bignum_clear(struct bignum *s)
{
	mbedtls_mpi *bn = (mbedtls_mpi *)s;

	bn->s = 1;
	if (bn->p)
		memset(bn->p, 0, sizeof(*bn->p) * bn->n);
}
