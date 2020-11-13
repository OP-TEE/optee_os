// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <stdio.h>
#include <kernel/tee_common.h>
#include <kernel/chip_services.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <kernel/tee_common_otp.h>
#include <trace.h>

static uint8_t tee_b2hs_add_base(uint8_t in)
{
	if (in > 9)
		return in + 55;
	else
		return in + 48;
}

static int tee_hs2b_rem_base(uint8_t in, uint8_t *out)
{
	if (in < 48 || in > 70 || (in > 57 && in < 65))
		return -1;

	if (in < 58)
		*out = in - 48;
	else
		*out = in - 55;

	return 0;
}

uint32_t tee_b2hs(uint8_t *b, uint8_t *hs, uint32_t blen, uint32_t hslen)
{
	uint32_t i = 0;

	if (blen * 2 + 1 > hslen)
		return 0;

	for (; i < blen; i++) {
		hs[i * 2 + 1] = tee_b2hs_add_base(b[i] & 0xf);
		hs[i * 2] = tee_b2hs_add_base(b[i] >> 4);
	}
	hs[blen * 2] = 0;

	return blen * 2;
}

uint32_t tee_hs2b(uint8_t *hs, uint8_t *b, uint32_t hslen, uint32_t blen)
{
	uint32_t i = 0;
	uint32_t len = TEE_HS2B_BBUF_SIZE(hslen);
	uint8_t hi;
	uint8_t lo;

	if (len > blen)
		return 0;

	for (; i < len; i++) {
		if (tee_hs2b_rem_base(hs[i * 2], &hi))
			return 0;
		if (tee_hs2b_rem_base(hs[i * 2 + 1], &lo))
			return 0;
		b[i] = (hi << 4) + lo;
	}

	return len;
}

static bool is_valid_conf_and_notnull_size(paddr_t b, paddr_size_t bl,
					   paddr_t a, paddr_size_t al)
{
	/* invalid config return false */
	if ((b - 1 + bl < b) || (a - 1 + al < a))
		return false;
	/* null sized areas are never inside / outside / overlap */
	if (!bl || !al)
		return false;
	return true;
}

/* Returns true when buffer 'b' is fully contained in area 'a' */
bool core_is_buffer_inside(paddr_t b, paddr_size_t bl,
			   paddr_t a, paddr_size_t al)
{
	/* invalid config or "null size" return false */
	if (!is_valid_conf_and_notnull_size(b, bl, a, al))
		return false;

	if ((b >= a) && (b - 1 + bl <= a - 1 + al))
		return true;
	return false;
}

/* Returns true when buffer 'b' is fully contained in area 'a' */
bool core_is_buffer_outside(paddr_t b, paddr_size_t bl,
			    paddr_t a, paddr_size_t al)
{
	/* invalid config or "null size" return false */
	if (!is_valid_conf_and_notnull_size(b, bl, a, al))
		return false;

	if ((b + bl - 1 < a) || (b > a + al - 1))
		return true;
	return false;
}

/* Returns true when buffer 'b' intersects area 'a' */
bool core_is_buffer_intersect(paddr_t b, paddr_size_t bl,
			      paddr_t a, paddr_size_t al)
{
	/* invalid config or "null size" return false */
	if (!is_valid_conf_and_notnull_size(b, bl, a, al))
		return false;

	if ((b + bl - 1 < a) || (b > a + al - 1))
		return false;
	return true;
}
