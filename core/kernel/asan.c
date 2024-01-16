// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/panic.h>
#include <string.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

#if __GCC_VERSION >= 70000
#define ASAN_ABI_VERSION 7
#else
#define ASAN_ABI_VERSION 6
#endif

struct asan_source_location {
	const char *file_name;
	int line_no;
	int column_no;
};

struct asan_global {
	uintptr_t beg;
	uintptr_t size;
	uintptr_t size_with_redzone;
	const char *name;
	const char *module_name;
	uintptr_t has_dynamic_init;
	struct asan_source_location *location;
#if ASAN_ABI_VERSION >= 7
	uintptr_t odr_indicator;
#endif
};

static vaddr_t asan_va_base;
static size_t asan_va_size;
static bool asan_active;

static int8_t *va_to_shadow(const void *va)
{
	vaddr_t sa = ((vaddr_t)va / ASAN_BLOCK_SIZE) + CFG_ASAN_SHADOW_OFFSET;

	return (int8_t *)sa;
}

static size_t va_range_to_shadow_size(const void *begin, const void *end)
{
	return ((vaddr_t)end - (vaddr_t)begin) / ASAN_BLOCK_SIZE;
}

static bool va_range_inside_shadow(const void *begin, const void *end)
{
	vaddr_t b = (vaddr_t)begin;
	vaddr_t e = (vaddr_t)end;

	if (b >= e)
		return false;
	return (b >= asan_va_base) && (e <= (asan_va_base + asan_va_size));
}

static bool va_range_outside_shadow(const void *begin, const void *end)
{
	vaddr_t b = (vaddr_t)begin;
	vaddr_t e = (vaddr_t)end;

	if (b >= e)
		return false;
	return (e <= asan_va_base) || (b >= (asan_va_base + asan_va_size));
}

static size_t va_misalignment(const void *va)
{
	return (vaddr_t)va & ASAN_BLOCK_MASK;
}

static bool va_is_well_aligned(const void *va)
{
	return !va_misalignment(va);
}

void asan_set_shadowed(const void *begin, const void *end)
{
	vaddr_t b = (vaddr_t)begin;
	vaddr_t e = (vaddr_t)end;

	assert(!asan_va_base);
	assert(va_is_well_aligned(begin));
	assert(va_is_well_aligned(end));
	assert(b < e);

	asan_va_base = b;
	asan_va_size = e - b;
}

void asan_tag_no_access(const void *begin, const void *end)
{
	assert(va_is_well_aligned(begin));
	assert(va_is_well_aligned(end));
	assert(va_range_inside_shadow(begin, end));

	asan_memset_unchecked(va_to_shadow(begin), ASAN_DATA_RED_ZONE,
			      va_range_to_shadow_size(begin, end));
}

void asan_tag_access(const void *begin, const void *end)
{
	if (!asan_va_base || (begin == end))
		return;

	assert(va_range_inside_shadow(begin, end));
	assert(va_is_well_aligned(begin));

	asan_memset_unchecked(va_to_shadow(begin), 0,
			      va_range_to_shadow_size(begin, end));
	if (!va_is_well_aligned(end))
		*va_to_shadow(end) = ASAN_BLOCK_SIZE - va_misalignment(end);
}

void asan_tag_heap_free(const void *begin, const void *end)
{
	if (!asan_va_base)
		return;

	assert(va_range_inside_shadow(begin, end));
	assert(va_is_well_aligned(begin));
	assert(va_is_well_aligned(end));

	asan_memset_unchecked(va_to_shadow(begin), ASAN_HEAP_RED_ZONE,
			      va_range_to_shadow_size(begin, end));
}

__inhibit_loop_to_libcall void *asan_memset_unchecked(void *s, int c, size_t n)
{
	uint8_t *b = s;
	size_t m;

	for (m = 0; m < n; m++)
		b[m] = c;

	return s;
}

__inhibit_loop_to_libcall
void *asan_memcpy_unchecked(void *__restrict dst, const void *__restrict src,
			    size_t len)
{
	uint8_t *__restrict d = dst;
	const uint8_t *__restrict s = src;
	size_t n;

	for (n = 0; n < len; n++)
		d[n] = s[n];

	return dst;
}

void asan_start(void)
{
	assert(asan_va_base && !asan_active);
	asan_active = true;
}

static void check_access(vaddr_t addr, size_t size)
{
	void *begin = (void *)addr;
	void *end = (void *)(addr + size);
	int8_t *a;
	int8_t *e;

	if (!asan_active || !size)
		return;
	if (va_range_outside_shadow(begin, end))
		return;
	/*
	 * If it isn't outside it has to be completely inside or there's a
	 * problem.
	 */
	if (!va_range_inside_shadow(begin, end))
		panic();

	e = va_to_shadow((void *)(addr + size - 1));
	for (a = va_to_shadow(begin); a <= e; a++)
		if (*a < 0)
			panic();

	if (!va_is_well_aligned(end) &&
	    va_misalignment(end) > (size_t)(*e - ASAN_BLOCK_SIZE))
		panic();
}

static void check_load(vaddr_t addr, size_t size)
{
	check_access(addr, size);
}

static void check_store(vaddr_t addr, size_t size)
{
	check_access(addr, size);
}

static void __noreturn report_load(vaddr_t addr __unused, size_t size __unused)
{
	panic();
}

static void __noreturn report_store(vaddr_t addr __unused, size_t size __unused)
{
	panic();
}



#define DEFINE_ASAN_FUNC(type, size)				\
	void __asan_##type##size(vaddr_t addr);			\
	void __asan_##type##size(vaddr_t addr)			\
	{ check_##type(addr, size); }				\
	void __asan_##type##size##_noabort(vaddr_t addr);	\
	void __asan_##type##size##_noabort(vaddr_t addr)	\
	{ check_##type(addr, size); }				\
	void __asan_report_##type##size##_noabort(vaddr_t addr);\
	void __noreturn __asan_report_##type##size##_noabort(vaddr_t addr) \
	{ report_##type(addr, size); }

DEFINE_ASAN_FUNC(load, 1)
DEFINE_ASAN_FUNC(load, 2)
DEFINE_ASAN_FUNC(load, 4)
DEFINE_ASAN_FUNC(load, 8)
DEFINE_ASAN_FUNC(load, 16)
DEFINE_ASAN_FUNC(store, 1)
DEFINE_ASAN_FUNC(store, 2)
DEFINE_ASAN_FUNC(store, 4)
DEFINE_ASAN_FUNC(store, 8)
DEFINE_ASAN_FUNC(store, 16)

void __asan_loadN_noabort(vaddr_t addr, size_t size);
void __asan_loadN_noabort(vaddr_t addr, size_t size)
{
	check_load(addr, size);
}

void __asan_storeN_noabort(vaddr_t addr, size_t size);
void __asan_storeN_noabort(vaddr_t addr, size_t size)
{
	check_store(addr, size);
}

void __asan_report_load_n_noabort(vaddr_t addr, size_t size);
void __noreturn __asan_report_load_n_noabort(vaddr_t addr, size_t size)
{
	report_load(addr, size);
}

void __asan_report_store_n_noabort(vaddr_t addr, size_t size);
void __noreturn __asan_report_store_n_noabort(vaddr_t addr, size_t size)
{
	report_store(addr, size);
}

void __asan_handle_no_return(void);
void __asan_handle_no_return(void)
{
}

void __asan_register_globals(struct asan_global *globals, size_t size);
void __asan_register_globals(struct asan_global *globals, size_t size)
{
	size_t n;

	for (n = 0; n < size; n++)
		asan_tag_access((void *)globals[n].beg,
				(void *)(globals[n].beg + globals[n].size));
}
DECLARE_KEEP_INIT(__asan_register_globals);

void __asan_unregister_globals(struct asan_global *globals, size_t size);
void __asan_unregister_globals(struct asan_global *globals __unused,
			       size_t size __unused)
{
}
