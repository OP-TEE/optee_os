// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2018-2020 Maxime Villard, m00nbsd.net
 */

#include <asan.h>
#include <assert.h>
#include <compiler.h>
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

#if defined(__KERNEL__)
# include <keep.h>
# include <kernel/panic.h>
#elif defined(__LDELF__)
# include <ldelf_syscalls.h>
# include <ldelf.h>
#else
# error "Not implemented"
#endif

#ifndef __KERNEL__
/* Stub for non-kernel builds */
#define DECLARE_KEEP_INIT(x)
#endif

#ifndef SMALL_PAGE_SIZE
#define SMALL_PAGE_SIZE 4096
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

#ifdef __KERNEL__
static struct asan_global_info __asan_global_info;
#endif

static bool asan_active;
static asan_panic_cb_t asan_panic_cb = asan_panic;

void __noreturn asan_panic(void)
{
#if defined(__KERNEL__)
	panic();
#elif defined(__LDELF__)
	_ldelf_panic(2);
#else
#error "Not implemented"
#endif
	/*
	 * _utee_panic (which will be used here) is not marked as noreturn.
	 * See _utee_panic prototype in utee_syscalls.h for reasoning. To
	 * prevent "‘noreturn’ function does return" warning the while loop
	 * is used.
	 */
	while (1)
		;
}

static bool addr_crosses_scale_boundary(vaddr_t addr, size_t size)
{
	return (addr >> ASAN_BLOCK_SHIFT) !=
	       ((addr + size - 1) >> ASAN_BLOCK_SHIFT);
}

static int8_t *va_to_shadow(const void *va)
{
#if defined(__KERNEL__)
	vaddr_t sa = ((vaddr_t)va / ASAN_BLOCK_SIZE) + CFG_ASAN_SHADOW_OFFSET;
#else
	vaddr_t sa = ((vaddr_t)va / ASAN_BLOCK_SIZE) + CFG_USER_ASAN_SHADOW_OFFSET;
#endif
	return (int8_t *)sa;
}

static size_t va_range_to_shadow_size(const void *begin, const void *end)
{
	return ((vaddr_t)end - (vaddr_t)begin) / ASAN_BLOCK_SIZE;
}

static bool va_range_inside_shadow(const void *begin, const void *end)
{
	struct asan_va_reg *regs = GET_ASAN_INFO()->regs;
	vaddr_t b = (vaddr_t)begin;
	vaddr_t e = (vaddr_t)end;
	unsigned int i = 0;

	if (b >= e)
		return false;

	for (i = 0; i < GET_ASAN_INFO()->regs_count; i++) {
		if (b >= regs[i].lo && e <= regs[i].hi) {
			/* Access is covered fully by at least one region */
			return true;
		}
	}

	return false;
}

static bool va_range_outside_shadow(const void *begin, const void *end)
{
	struct asan_va_reg *regs = GET_ASAN_INFO()->regs;
	vaddr_t b = (vaddr_t)begin;
	vaddr_t e = (vaddr_t)end;
	unsigned int i = 0;

	if (b >= e)
		return false;

	for (i = 0; i < GET_ASAN_INFO()->regs_count; i++) {
		if (b < regs[i].hi && e > regs[i].lo) {
			/* Access covers region at least partly */
			return false;
		}
	}

	return true;
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
	struct asan_va_reg reg = {(vaddr_t)begin, (vaddr_t)end};
	struct asan_global_info *asan_info = GET_ASAN_INFO();

	assert(va_is_well_aligned(begin));
	assert(va_is_well_aligned(end));
	assert(reg.lo < reg.hi);
	if (asan_info->regs_count < ASAN_VA_REGS_MAX) {
		asan_info->regs[asan_info->regs_count++] = reg;
	} else {
		EMSG("No free regions to allocate");
		asan_panic();
	}
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
	if (!GET_ASAN_INFO()->regs_count || begin == end)
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
	if (!GET_ASAN_INFO()->regs_count)
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
	assert(GET_ASAN_INFO()->regs_count > 0 && !asan_active);
	asan_active = true;
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
		asan_panic();

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
	asan_panic();
}

static void __noreturn report_store(vaddr_t addr __unused, size_t size __unused)
{
	asan_panic();
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

#if !defined(__KERNEL__)

static int asan_map_shadow_region(vaddr_t lo, vaddr_t hi)
{
	struct asan_global_info *asan_info = GET_ASAN_INFO();
	size_t sz = (size_t)(hi - lo);
	TEE_Result rc = TEE_SUCCESS;
	vaddr_t req = lo;

	if (asan_info->s_regs_count >= ASAN_VA_REGS_MAX)
		return -1;

#if defined(__LDELF__)
	rc = _ldelf_map_zi(&req, sz, 0, 0, 0);
#else
#error "Not implemented"
#endif
	if (rc != TEE_SUCCESS)
		return -1;
	if (req != lo)
		return -1;

	asan_info->s_regs[asan_info->s_regs_count++] = (struct asan_va_reg){ lo, hi };

	return 0;
}

int asan_user_map_shadow(void *lo, void *hi)
{
	vaddr_t lo_s = ROUNDDOWN((vaddr_t)va_to_shadow(lo), SMALL_PAGE_SIZE);
	vaddr_t hi_s = ROUNDUP((vaddr_t)va_to_shadow(hi), SMALL_PAGE_SIZE);
	int rc = 0;

	if (lo_s >= hi_s)
		return -1;
	if (hi >= (void *)GET_ASAN_INFO())
		return -1;

	for (size_t i = 0; i < GET_ASAN_INFO()->s_regs_count; i++) {
		vaddr_t reg_lo_s = GET_ASAN_INFO()->s_regs[i].lo;
		vaddr_t reg_hi_s = GET_ASAN_INFO()->s_regs[i].hi;

		if (reg_hi_s <= lo_s || reg_lo_s >= hi_s) {
			/* (1) no overlap */
			continue;
		}
		if (reg_lo_s <= lo_s && reg_hi_s >= hi_s) {
			/* (2) existing fully covers the requested interval */
			asan_set_shadowed(lo, hi);
			return 0;
		}
		if (reg_lo_s <= lo_s && reg_hi_s < hi_s) {
			/* (3) left overlap */
			lo_s = reg_hi_s;
			continue;
		}
		if (reg_lo_s > lo_s && reg_hi_s >= hi_s) {
			/* (4) right overlap */
			hi_s = reg_lo_s;
			continue;
		}
		if (reg_lo_s >= lo_s && reg_hi_s <= hi_s) {
			/* (5) existing fully inside requested interval */
			rc = asan_map_shadow_region(reg_hi_s, hi_s);
			if (rc) {
				EMSG("%s: Failed to map shadow region",
				     __func__);
				asan_panic();
			}
			hi_s = reg_lo_s;
			continue;
		}
		EMSG("%s: can't handle: reg_lo_s %#"PRIxVA
		     " reg_hi_s %#"PRIxVA" lo_s %#"PRIxVA" hi_s %#"
		     PRIxVA, __func__, reg_lo_s, reg_hi_s, lo_s,
		     hi_s);
		asan_panic();
	}

	/* If there is something to map */
	if (hi_s > lo_s) {
		rc = asan_map_shadow_region(lo_s, hi_s);
		assert(!rc);
	}
	if (!rc) {
		/* Add region to allowed regions list */
		asan_set_shadowed(lo, hi);
	}

	return rc;
}

#else

int asan_user_map_shadow(void *lo __unused, void *hi __unused)
{
	return 0;
}
#endif
