// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, STMicroelectronics International N.V.
 */

/* struct lqr - stores qutient/remainder to handle divmod EABI interfaces. */
struct lqr {
	unsigned long long q;	/* computed quotient */
	unsigned long long r;	/* computed remainder */
	unsigned q_n;		/* specficies if quotient shall be negative */
	unsigned r_n;		/* specficies if remainder shall be negative */
};

static void ul_div_qr(unsigned long long numerator,
		unsigned long long denominator, struct lqr *qr);


static void division_lqr(unsigned long long n, unsigned long long p,
		struct lqr *qr)
{
	unsigned long long i = 1, q = 0;
	if (p == 0) {
		qr->r = 0xFFFFFFFFFFFFFFFFULL;	/* division by 0 */
		return;
	}

	while ((p >> 63) == 0) {
		i = i << 1;	/* count the max division steps */
		p = p << 1;     /* increase p until it has maximum size*/
	}

	while (i > 0) {
		q = q << 1;	/* write bit in q at index (size-1) */
		if (n >= p) {
			n -= p;
			q++;
		}
		p = p >> 1;	/* decrease p */
		i = i >> 1;	/* decrease remaining size in q */
	}
	qr->r = n;
	qr->q = q;
}

static void ul_div_qr(unsigned long long numerator,
		unsigned long long denominator, struct lqr *qr)
{

	division_lqr(numerator, denominator, qr);

	/* negate quotient and/or remainder according to requester */
	if (qr->q_n)
		qr->q = -qr->q;
	if (qr->r_n)
		qr->r = -qr->r;
}

struct asm_ulqr {
	unsigned long long v0;
	unsigned long long v1;
};

/* called from assembly function __aeabi_uldivmod */
void __ul_divmod(struct asm_ulqr *asm_ulqr);
void __ul_divmod(struct asm_ulqr *asm_ulqr)
{
	unsigned long long numerator = asm_ulqr->v0;
	unsigned long long denominator = asm_ulqr->v1;
	struct lqr qr = { .q_n = 0, .r_n = 0 };

	ul_div_qr(numerator, denominator, &qr);

	asm_ulqr->v0 = qr.q;
	asm_ulqr->v1 = qr.r;
}

struct asm_lqr {
	long long v0;
	long long v1;
};

/* called from assembly function __aeabi_ldivmod */
void __l_divmod(struct asm_lqr *asm_lqr);
void __l_divmod(struct asm_lqr *asm_lqr)
{
	long long numerator = asm_lqr->v0;
	long long denominator = asm_lqr->v1;
	struct lqr qr = { .q_n = 0, .r_n = 0 };

	if (((numerator < 0) && (denominator > 0)) ||
	    ((numerator > 0) && (denominator < 0)))
		qr.q_n = 1;	/* quotient shall be negate */
	if (numerator < 0) {
		numerator = -numerator;
		qr.r_n = 1;	/* remainder shall be negate */
	}
	if (denominator < 0)
		denominator = -denominator;

	ul_div_qr(numerator, denominator, &qr);

	asm_lqr->v0 = qr.q;
	asm_lqr->v1 = qr.r;
}
