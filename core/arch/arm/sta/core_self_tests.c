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
#include <malloc.h>
#include <stdbool.h>
#include <trace.h>
#include "core_self_tests.h"

/*
 * Enable expect LOG macro to enable/disable self tests traces.
 *
 * #define LOG     DMSG_RAW
 * #define LOG(...)
 */
#define LOG(...)

static int self_test_division(void);
static int self_test_malloc(void);

/* exported entry points for some basic test */
TEE_Result core_self_tests(uint32_t nParamTypes __unused,
		TEE_Param pParams[TEE_NUM_PARAMS] __unused)
{
	if (self_test_division() || self_test_malloc()) {
		EMSG("some self_test_xxx failed! you should enable local LOG");
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
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

	LOG("malloc tests (malloc, free, calloc, realloc, memalign):");
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
	p1 = realloc(p1, 3 * 1024);
	LOG("- p1 = realloc(p1, 3*1024)");
	LOG("- free p2");
	free(p2);
	p2 = malloc(1024);
	LOG("- p2 = malloc(1024)");
	LOG("  p1=%p  p2=%p  p3=%p  p4=%p",
	    (void *)p1, (void *)p2, (void *)p3, (void *)p4);
	r = (p1 && p2);
	if (!r)
		ret = -1;
	LOG("  => test %s", r ? "ok" : "FAILED");
	LOG("");
	LOG("- free p1, p2");
	free(p1);
	free(p2);
	p1 = NULL;
	p2 = NULL;

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
