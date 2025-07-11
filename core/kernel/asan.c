// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2018-2020 Maxime Villard, m00nbsd.net
 */

#include <assert.h>
#include <compiler.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/panic.h>
#include <printk.h>
#include <setjmp.h>
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
static asan_panic_cb_t asan_panic_cb = asan_panic;

static bool addr_crosses_scale_boundary(vaddr_t addr, size_t size)
{
	return (addr >> ASAN_BLOCK_SHIFT) !=
	       ((addr + size - 1) >> ASAN_BLOCK_SHIFT);
}

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
		*va_to_shadow(end) = va_misalignment(end);
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

void __noreturn asan_panic(void)
{
	panic();
}

void asan_set_panic_cb(asan_panic_cb_t panic_cb)
{
	asan_panic_cb = panic_cb;
}

static void asan_report(vaddr_t addr, size_t size)
{
#ifdef KASAN_DUMP_SHADOW
	char buf[128] = {0};
	int r = 0, rc = 0;
	vaddr_t b = 0, e = 0, saddr = 0;

	b = ROUNDDOWN(addr, ASAN_BLOCK_SIZE) - ASAN_BLOCK_SIZE;
	e = ROUNDDOWN(addr, ASAN_BLOCK_SIZE) + ASAN_BLOCK_SIZE;

	/* Print shadow map nearby */
	if (va_range_inside_shadow((void *)b, (void *)e)) {
		rc = snprintk(buf + r, sizeof(buf) - r, "%lx: ", b);
		assert(rc > 0);
		r += rc;
		for (saddr = b; saddr <= e; saddr += ASAN_BLOCK_SIZE) {
			int8_t *sbyte = va_to_shadow((void *)saddr);

			rc = snprintk(buf + r, sizeof(buf) - r,
				      "0x%02x ", (uint8_t)*sbyte);
			assert(rc > 0);
			r += rc;
		}
		EMSG("%s", buf);
	}
#endif
	EMSG("[ASAN]: access violation, addr: %lx size: %zu\n",
	     addr, size);

	asan_panic_cb();
}

static __always_inline bool asan_shadow_1byte_isvalid(vaddr_t addr)
{
	int8_t last = (addr & ASAN_BLOCK_MASK) + 1;
	int8_t *byte = va_to_shadow((void *)addr);

	if (*byte == 0 || last <= *byte)
		return true;

	return false;
}

static __always_inline bool asan_shadow_2byte_isvalid(vaddr_t addr)
{
	if (addr_crosses_scale_boundary(addr, 2)) {
		return (asan_shadow_1byte_isvalid(addr) &&
			asan_shadow_1byte_isvalid(addr + 1));
	} else {
		int8_t last = ((addr + 1) & ASAN_BLOCK_MASK) + 1;
		int8_t *byte = va_to_shadow((void *)addr);

		if (*byte == 0 || last <= *byte)
			return true;

		return false;
	}
}

static __always_inline bool asan_shadow_4byte_isvalid(vaddr_t addr)
{
	if (addr_crosses_scale_boundary(addr, 4)) {
		return (asan_shadow_2byte_isvalid(addr) &&
			asan_shadow_2byte_isvalid(addr + 2));
	} else {
		int8_t last = ((addr + 3) & ASAN_BLOCK_MASK) + 1;
		int8_t *byte = va_to_shadow((void *)addr);

		if (*byte == 0 || last <= *byte)
			return true;

		return false;
	}
}

static __always_inline bool asan_shadow_8byte_isvalid(vaddr_t addr)
{
	if (addr_crosses_scale_boundary(addr, 8)) {
		return (asan_shadow_4byte_isvalid(addr) &&
			asan_shadow_4byte_isvalid(addr + 4));
	} else {
		int8_t last = ((addr + 7) & ASAN_BLOCK_MASK) + 1;
		int8_t *byte = va_to_shadow((void *)addr);

		if (*byte == 0 || last <= *byte)
			return true;

		return false;
	}
}

static __always_inline bool asan_shadow_Nbyte_isvalid(vaddr_t addr,
						      size_t size)
{
	size_t i = 0;

	for (; i < size; i++) {
		if (!asan_shadow_1byte_isvalid(addr + i))
			return false;
	}

	return true;
}

static __always_inline void check_access(vaddr_t addr, size_t size)
{
	bool valid = false;
	void *begin = (void *)addr;
	void *end = (void *)(addr + size);

	if (!asan_active)
		return;
	if (size == 0)
		return;
	if (va_range_outside_shadow(begin, end))
		return;
	/*
	 * If it isn't outside it has to be completely inside or there's a
	 * problem.
	 */
	if (!va_range_inside_shadow(begin, end))
		panic();

	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			valid = asan_shadow_1byte_isvalid(addr);
			break;
		case 2:
			valid = asan_shadow_2byte_isvalid(addr);
			break;
		case 4:
			valid = asan_shadow_4byte_isvalid(addr);
			break;
		case 8:
			valid = asan_shadow_8byte_isvalid(addr);
			break;
		default:
			valid = asan_shadow_Nbyte_isvalid(addr, size);
			break;
		}
	} else {
		valid = asan_shadow_Nbyte_isvalid(addr, size);
	}

	if (!valid)
		asan_report(addr, size);
}

static __always_inline void check_load(vaddr_t addr, size_t size)
{
	check_access(addr, size);
}

static __always_inline void check_store(vaddr_t addr, size_t size)
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
	size_t n = 0;

	for (n = 0; n < size; n++) {
		vaddr_t begin = globals[n].beg;
		vaddr_t end = begin + globals[n].size;
		vaddr_t end_align = ROUNDUP(end, ASAN_BLOCK_SIZE);
		vaddr_t end_rz = begin + globals[n].size_with_redzone;

		asan_tag_access((void *)begin, (void *)end);
		asan_tag_no_access((void *)end_align, (void *)end_rz);
	}
}
DECLARE_KEEP_INIT(__asan_register_globals);

void __asan_unregister_globals(struct asan_global *globals, size_t size);
void __asan_unregister_globals(struct asan_global *globals __unused,
			       size_t size __unused)
{
}

void asan_handle_longjmp(void *old_sp)
{
	void *top = old_sp;
	void *bottom = (void *)ROUNDDOWN((vaddr_t)&top,
					 ASAN_BLOCK_SIZE);

	asan_tag_access(bottom, top);
}
