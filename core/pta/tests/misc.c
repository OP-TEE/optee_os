// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#include <assert.h>
#include <config.h>
#include <kernel/dt_driver.h>
#include <malloc.h>
#include <stdbool.h>
#include <trace.h>
#include <kernel/panic.h>
#include <util.h>

#include "misc.h"

/*
 * Enable expect LOG macro to enable/disable self tests traces.
 *
 * #define LOG     DMSG_RAW
 * #define LOG(...)
 */
#define LOG(...)

static int self_test_add_overflow(void)
{
	uint32_t r_u32;
	int32_t r_s32;
	uintmax_t r_um;
	intmax_t r_sm;

	if (ADD_OVERFLOW(8U, 0U, &r_s32))
		return -1;
	if (r_s32 != 8)
		return -1;
	if (ADD_OVERFLOW(32U, 30U, &r_u32))
		return -1;
	if (r_u32 != 62)
		return -1;
	if (!ADD_OVERFLOW(UINT32_MAX, UINT32_MAX, &r_u32))
		return -1;
	if (!ADD_OVERFLOW(UINT32_MAX / 2 + 1, UINT32_MAX / 2 + 1, &r_u32))
		return -1;
	if (ADD_OVERFLOW(UINT32_MAX / 2, UINT32_MAX / 2 + 1, &r_u32))
		return -1;
	if (r_u32 != UINT32_MAX)
		return -1;

	if (ADD_OVERFLOW((uint32_t)30, (int32_t)-31, &r_s32))
		return -1;
	if (r_s32 != -1)
		return -1;
	if (ADD_OVERFLOW((int32_t)30, (int32_t)-31, &r_s32))
		return -1;
	if (r_s32 != -1)
		return -1;
	if (ADD_OVERFLOW((int32_t)-31, (uint32_t)30, &r_s32))
		return -1;
	if (r_s32 != -1)
		return -1;

	if (ADD_OVERFLOW(INT32_MIN + 1, -1, &r_s32))
		return -1;
	if (r_s32 != INT32_MIN)
		return -1;
	if (!ADD_OVERFLOW(INT32_MIN, -1, &r_s32))
		return -1;
	if (!ADD_OVERFLOW(INT32_MIN + 1, -2, &r_s32))
		return -1;
	if (!ADD_OVERFLOW(INT32_MAX, INT32_MAX, &r_s32))
		return -1;
	if (ADD_OVERFLOW(INT32_MAX, INT32_MAX, &r_u32))
		return -1;
	if (!ADD_OVERFLOW(INTMAX_MAX, INTMAX_MAX, &r_sm))
		return -1;
	if (ADD_OVERFLOW(INTMAX_MAX, INTMAX_MAX, &r_um))
		return -1;
	if (!ADD_OVERFLOW(INT32_MAX / 2 + 1, INT32_MAX / 2 + 1, &r_s32))
		return -1;
	if (ADD_OVERFLOW(INT32_MAX / 2, INT32_MAX / 2 + 1, &r_s32))
		return -1;
	if (r_s32 != INT32_MAX)
		return -1;

	return 0;
}

static int self_test_sub_overflow(void)
{
	uint32_t r_u32;
	int32_t r_s32;
	intmax_t r_sm;

	if (SUB_OVERFLOW(8U, 1U, &r_s32))
		return -1;
	if (r_s32 != 7)
		return -1;
	if (SUB_OVERFLOW(32U, 30U, &r_u32))
		return -1;
	if (r_u32 != 2)
		return -1;
	if (!SUB_OVERFLOW(30U, 31U, &r_u32))
		return -1;

	if (SUB_OVERFLOW(30, 31, &r_s32))
		return -1;
	if (r_s32 != -1)
		return -1;
	if (SUB_OVERFLOW(-1, INT32_MAX, &r_s32))
		return -1;
	if (r_s32 != INT32_MIN)
		return -1;
	if (!SUB_OVERFLOW(-2, INT32_MAX, &r_s32))
		return -1;

	if (SUB_OVERFLOW((uint32_t)30, (int32_t)-31, &r_s32))
		return -1;
	if (r_s32 != 61)
		return -1;
	if (SUB_OVERFLOW((int32_t)30, (int32_t)-31, &r_s32))
		return -1;
	if (r_s32 != 61)
		return -1;
	if (SUB_OVERFLOW((int32_t)-31, (uint32_t)30, &r_s32))
		return -1;
	if (r_s32 != -61)
		return -1;
	if (SUB_OVERFLOW((int32_t)-31, (int32_t)-30, &r_s32))
		return -1;
	if (r_s32 != -1)
		return -1;

	if (SUB_OVERFLOW((int32_t)31, -(INTMAX_MIN + 1), &r_sm))
		return -1;
	if (r_sm != (INTMAX_MIN + 32))
		return -1;

	return 0;
}

static int self_test_mul_unsigned_overflow(void)
{
	const size_t um_half_shift = sizeof(uintmax_t) * 8 / 2;
	const uintmax_t um_half_mask = UINTMAX_MAX >> um_half_shift;
	uint32_t r_u32;
	uintmax_t r_um;

	if (MUL_OVERFLOW(32, 30, &r_u32))
		return -1;
	if (r_u32 != 960)
		return -1;
	if (MUL_OVERFLOW(-32, -30, &r_u32))
		return -1;
	if (r_u32 != 960)
		return -1;

	if (MUL_OVERFLOW(UINTMAX_MAX, 1, &r_um))
		return -1;
	if (r_um != UINTMAX_MAX)
		return -1;
	if (MUL_OVERFLOW(UINTMAX_MAX / 4, 4, &r_um))
		return -1;
	if (r_um != (UINTMAX_MAX - 3))
		return -1;
	if (!MUL_OVERFLOW(UINTMAX_MAX / 4 + 1, 4, &r_um))
		return -1;
	if (!MUL_OVERFLOW(UINTMAX_MAX, UINTMAX_MAX, &r_um))
		return -1;
	if (!MUL_OVERFLOW(um_half_mask << um_half_shift,
			  um_half_mask << um_half_shift, &r_um))
		return -1;

	return 0;
}

static int self_test_mul_signed_overflow(void)
{
	intmax_t r;

	if (MUL_OVERFLOW(32, -30, &r))
		return -1;
	if (r != -960)
		return -1;
	if (MUL_OVERFLOW(-32, 30, &r))
		return -1;
	if (r != -960)
		return -1;
	if (MUL_OVERFLOW(32, 30, &r))
		return -1;
	if (r != 960)
		return -1;

	if (MUL_OVERFLOW(INTMAX_MAX, 1, &r))
		return -1;
	if (r != INTMAX_MAX)
		return -1;
	if (MUL_OVERFLOW(INTMAX_MAX / 4, 4, &r))
		return -1;
	if (r != (INTMAX_MAX - 3))
		return -1;
	if (!MUL_OVERFLOW(INTMAX_MAX / 4 + 1, 4, &r))
		return -1;
	if (!MUL_OVERFLOW(INTMAX_MAX, INTMAX_MAX, &r))
		return -1;
	if (MUL_OVERFLOW(INTMAX_MIN + 1, 1, &r))
		return -1;
	if (r != INTMAX_MIN + 1)
		return -1;
	if (MUL_OVERFLOW(1, INTMAX_MIN + 1, &r))
		return -1;
	if (r != INTMAX_MIN + 1)
		return -1;
	if (MUL_OVERFLOW(0, INTMAX_MIN, &r))
		return -1;
	if (r != 0)
		return -1;
	if (MUL_OVERFLOW(1, INTMAX_MIN, &r))
		return -1;
	if (r != INTMAX_MIN)
		return -1;

	return 0;
}

/* test division support. resulting trace shall be manually checked */
static int self_test_division(void)
{
	signed a, b, c, d;
	bool r;
	int ret = 0;

	LOG("");
	LOG("division tests (division and modulo):");
	/* get some unpredicted values to prevent compilation optimizations: */
	/* => use the stack address */

	LOG("- test with unsigned small integers:");
	a = (signed)((unsigned)(vaddr_t)&a & 0xFFFFF);
	b = (signed)((unsigned)(vaddr_t)&b & 0x00FFF) + 1;
	c = a / b;
	d = a % b;
	r = ((b * c + d) == a);
	if (!r)
		ret = -1;
	LOG("  0x%08x / 0x%08x = %u / %u = %u = 0x%x)",
	    (unsigned)a, (unsigned)b, (unsigned)a, (unsigned)b, (unsigned)c,
	    (unsigned)c);
	LOG("  0x%08x %% 0x%08x = %u %% %u = %u = 0x%x)", (unsigned)a,
	    (unsigned)b, (unsigned)a, (unsigned)b, (unsigned)d, (unsigned)d);
	LOG("  check results => %s", r ? "ok" : "FAILED !!!");
	LOG("");

	LOG("- test with signed small integers, negative numerator:");
	a = (signed)(vaddr_t)&a;
	b = (signed)((unsigned)(vaddr_t)&b & 0x00FFF) - 1;
	c = a / b;
	d = a % b;
	r = ((b * c + d) == a);
	if (!r)
		ret = -1;
	LOG("  0x%08x / 0x%08x = %d / %d = %d = 0x%x)",
	    (unsigned)a, (unsigned)b, (signed)a, (signed)b, (signed)c,
	    (unsigned)c);
	LOG("  0x%08x %% 0x%08x = %d %% %d = %d = 0x%x)", (unsigned)a,
	    (unsigned)b, (signed)a, (signed)b, (signed)d, (unsigned)d);
	LOG("  check results => %s", r ? "ok" : "FAILED !!!");
	LOG("");

	LOG("- test with signed small integers, negative denominator:");
	a = (signed)((unsigned)(vaddr_t)&a & 0xFFFFF);
	b = -(signed)((unsigned)(vaddr_t)&b & 0x00FFF) + 1;
	c = a / b;
	d = a % b;

	LOG("- test with unsigned integers, big numerator (> 0x80000000):");
	a = (signed)(vaddr_t)&a;
	b = (signed)((unsigned)(vaddr_t)&b & 0x00FFF) + 1;
	c = (signed)((unsigned)a / (unsigned)b);
	d = (signed)((unsigned)a % (unsigned)b);
	r = (((unsigned)b * (unsigned)c + (unsigned)d) == (unsigned)a);
	if (!r)
		ret = -1;
	LOG("  0x%08x / 0x%08x = %u / %u = %u = 0x%x)",
	    (unsigned)a, (unsigned)b, (unsigned)a, (unsigned)b, (unsigned)c,
	    (unsigned)c);
	LOG("  0x%08x %% 0x%08x = %u %% %u = %u = 0x%x)", (unsigned)a,
	    (unsigned)b, (unsigned)a, (unsigned)b, (unsigned)d, (unsigned)d);
	LOG("  check results => %s", r ? "ok" : "FAILED !!!");
	LOG("");

	LOG("- test with unsigned integers, big num. & denom. (> 0x80000000):");
	a = (signed)(vaddr_t)&a;
	b = (signed)((unsigned)(vaddr_t)&a - 1);
	c = (signed)((unsigned)a / (unsigned)b);
	d = (signed)((unsigned)a % (unsigned)b);
	r = (((unsigned)b * (unsigned)c + (unsigned)d) == (unsigned)a);
	if (!r)
		ret = -1;
	LOG("  0x%08x / 0x%08x = %u / %u = %u = 0x%x)",
	    (unsigned)a, (unsigned)b, (unsigned)a, (unsigned)b, (unsigned)c,
	    (unsigned)c);
	LOG("  0x%08x %% 0x%08x = %u %% %u = %u = 0x%x)", (unsigned)a,
	    (unsigned)b, (unsigned)a, (unsigned)b, (unsigned)d, (unsigned)d);
	LOG("  check results => %s", r ? "ok" : "FAILED !!!");
	LOG("");

	return ret;
}

/* test malloc support. resulting trace shall be manually checked */
static int self_test_malloc(void)
{
	char *p1 = NULL, *p2 = NULL;
	int *p3 = NULL, *p4 = NULL;
	bool r;
	int ret = 0;

	LOG("malloc tests:");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	/* test malloc */
	p1 = malloc(1024);
	LOG("- p1 = malloc(1024)");
	p2 = malloc(1024);
	LOG("- p2 = malloc(1024)");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p1 && p2 && malloc_buffer_is_within_alloced(p1, 1024) &&
		!malloc_buffer_is_within_alloced(p1 + 25, 1000) &&
		!malloc_buffer_is_within_alloced(p1 - 25, 500) &&
		malloc_buffer_overlaps_heap(p1 - 25, 500));
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");

	/* test realloc */
	p3 = realloc(p1, 3 * 1024);
	if (p3)
		p1 = NULL;
	LOG("- p3 = realloc(p1, 3*1024)");
	LOG("- free p2");
	free(p2);
	p2 = malloc(1024);
	LOG("- p2 = malloc(1024)");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p2 && p3);
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- free p1, p2, p3");
	free(p1);
	free(p2);
	free(p3);
	p1 = NULL;
	p2 = NULL;
	p3 = NULL;

	/* test calloc */
	p3 = calloc(4, 1024);
	p4 = calloc(0x100, 1024 * 1024);
	LOG("- p3 = calloc(4, 1024)");
	LOG("- p4 = calloc(0x100, 1024*1024)   too big: should fail!");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p3 && !p4);
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- free p3, p4");
	free(p3);
	free(p4);
	p3 = NULL;
	p4 = NULL;

	/* test memalign */
	p3 = memalign(0x1000, 1024);
	LOG("- p3 = memalign(%d, 1024)", 0x1000);
	p1 = malloc(1024);
	LOG("- p1 = malloc(1024)");
	p4 = memalign(0x100, 512);
	LOG("- p4 = memalign(%d, 512)", 0x100);
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p1 && p3 && p4 &&
	    !((vaddr_t)p3 % 0x1000) && !((vaddr_t)p4 % 0x100));
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- free p1, p3, p4");
	free(p1);
	free(p3);
	free(p4);
	p1 = NULL;
	p3 = NULL;
	p4 = NULL;

	/* test memalign with invalid alignments */
	p3 = memalign(100, 1024);
	LOG("- p3 = memalign(%d, 1024)", 100);
	p4 = memalign(0, 1024);
	LOG("- p4 = memalign(%d, 1024)", 0);
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (!p3 && !p4);
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- free p3, p4");
	free(p3);
	free(p4);
	p3 = NULL;
	p4 = NULL;

	/* test free(NULL) */
	LOG("- free NULL");
	free(NULL);
	LOG("");
	LOG("malloc test done");

	return ret;
}

#ifdef CFG_VIRTUALIZATION
/* test nex_malloc support. resulting trace shall be manually checked */
static int self_test_nex_malloc(void)
{
	char *p1 = NULL, *p2 = NULL;
	int *p3 = NULL, *p4 = NULL;
	bool r;
	int ret = 0;

	LOG("nex_malloc tests:");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	/* test malloc */
	p1 = nex_malloc(1024);
	LOG("- p1 = nex_malloc(1024)");
	p2 = nex_malloc(1024);
	LOG("- p2 = nex_malloc(1024)");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p1 && p2 && nex_malloc_buffer_is_within_alloced(p1, 1024) &&
		!nex_malloc_buffer_is_within_alloced(p1 + 25, 1000) &&
		!nex_malloc_buffer_is_within_alloced(p1 - 25, 500) &&
		nex_malloc_buffer_overlaps_heap(p1 - 25, 500));
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");

	/* test realloc */
	p3 = nex_realloc(p1, 3 * 1024);
	if (p3)
		p1 = NULL;
	LOG("- p3 = nex_realloc(p1, 3*1024)");
	LOG("- nex_free p2");
	nex_free(p2);
	p2 = nex_malloc(1024);
	LOG("- p2 = nex_malloc(1024)");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p2 && p3);
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- nex_free p1, p2, p3");
	nex_free(p1);
	nex_free(p2);
	nex_free(p3);
	p1 = NULL;
	p2 = NULL;
	p3 = NULL;

	/* test calloc */
	p3 = nex_calloc(4, 1024);
	p4 = nex_calloc(0x100, 1024 * 1024);
	LOG("- p3 = nex_calloc(4, 1024)");
	LOG("- p4 = nex_calloc(0x100, 1024*1024)   too big: should fail!");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p3 && !p4);
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- nex_free p3, p4");
	nex_free(p3);
	nex_free(p4);
	p3 = NULL;
	p4 = NULL;

	/* test memalign */
	p3 = nex_memalign(0x1000, 1024);
	LOG("- p3 = nex_memalign(%d, 1024)", 0x1000);
	p1 = nex_malloc(1024);
	LOG("- p1 = nex_malloc(1024)");
	p4 = nex_memalign(0x100, 512);
	LOG("- p4 = nex_memalign(%d, 512)", 0x100);
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p1 && p3 && p4 &&
	    !((vaddr_t)p3 % 0x1000) && !((vaddr_t)p4 % 0x100));
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- nex_free p1, p3, p4");
	nex_free(p1);
	nex_free(p3);
	nex_free(p4);
	p1 = NULL;
	p3 = NULL;
	p4 = NULL;

	/* test memalign with invalid alignments */
	p3 = nex_memalign(100, 1024);
	LOG("- p3 = nex_memalign(%d, 1024)", 100);
	p4 = nex_memalign(0, 1024);
	LOG("- p4 = nex_memalign(%d, 1024)", 0);
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (!p3 && !p4);
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- nex_free p3, p4");
	nex_free(p3);
	nex_free(p4);
	p3 = NULL;
	p4 = NULL;

	/* test free(NULL) */
	LOG("- nex_free NULL");
	nex_free(NULL);
	LOG("");
	LOG("nex_malloc test done");

	return ret;
}
#else  /* CFG_VIRTUALIZATION */
static int self_test_nex_malloc(void)
{
	return 0;
}
#endif

/* exported entry points for some basic test */
TEE_Result core_self_tests(uint32_t nParamTypes __unused,
		TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	if (self_test_mul_signed_overflow() || self_test_add_overflow() ||
	    self_test_sub_overflow() || self_test_mul_unsigned_overflow() ||
	    self_test_division() || self_test_malloc() ||
	    self_test_nex_malloc()) {
		EMSG("some self_test_xxx failed! you should enable local LOG");
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

/* Exported entrypoint for dt_driver tests */
TEE_Result core_dt_driver_tests(uint32_t nParamTypes __unused,
				TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	if (IS_ENABLED(CFG_DT_DRIVER_EMBEDDED_TEST)) {
		if (dt_driver_test_status())
			return TEE_ERROR_GENERIC;
	} else {
		IMSG("dt_driver tests are not embedded");
	}

	return TEE_SUCCESS;
}
