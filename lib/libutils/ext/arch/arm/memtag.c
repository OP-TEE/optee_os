// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <arm_user_sysreg.h>
#include <assert.h>
#include <config.h>
#include <memtag.h>
#include <string.h>

#if MEMTAG_IS_ENABLED

/* This is for AArch64 only, MTE is only available in this mode */

static unsigned int dczid_block_size(void)
{
	return SHIFT_U32(4U, read_dczid_el0() & 0xf);
}

static bool data_zero_prohibited(void)
{
#ifdef __KERNEL__
	return false;
#else
	return read_dczid_el0() & BIT(4);
#endif
}

static void dc_gzva(uint64_t va)
{
	asm volatile ("dc gzva, %0" : : "r" (va));
}

static void dc_gva(uint64_t va)
{
	asm volatile ("dc gva, %0" : : "r" (va));
}

static vaddr_t stg_and_advance(vaddr_t va)
{
	asm volatile("stg %0, [%0], #16" : "+r"(va) : : "memory");
	return va;
}

static void *insert_random_tag(void *addr)
{
	asm volatile("irg %0, %0" : "+r"(addr) : : );
	return addr;
}

static void *load_tag(void *addr)
{
	asm volatile("ldg %0, [%0]" : "+r"(addr) : : );
	return addr;
}

static void set_tags_dc_gva(vaddr_t va, size_t size, size_t dcsz)
{
	do {
		dc_gva(va);
		va += dcsz;
		size -= dcsz;
	} while (size);
}

static void clear_mem_dc_gzva(vaddr_t va, size_t size, size_t dcsz)
{
	do {
		dc_gzva(va);
		va += dcsz;
		size -= dcsz;
	} while (size);
}

static void *set_tags_helper(void *addr, size_t size)
{
	vaddr_t va = (vaddr_t)addr;
	vaddr_t end = va + size;

	assert(!(va & MEMTAG_GRANULE_MASK));
	assert(!(size & MEMTAG_GRANULE_MASK));

	while (va < end)
		va = stg_and_advance(va);

	return addr;
}

static void *set_tags_dc_helper(void *addr, size_t size)
{
	size_t dcsz = dczid_block_size();
	vaddr_t va = (vaddr_t)addr;
	size_t mask = dcsz - 1;
	size_t s = 0;

	if (va & mask) {
		s = MIN(dcsz - (va & mask), size);
		set_tags_helper((void *)va, s);
		va += s;
		size -= s;
	}
	s = size & ~mask;
	if (s) {
		set_tags_dc_gva(va, s, dcsz);
		va += s;
		size -= s;
	}
	if (size)
		set_tags_helper((void *)va, size);

	return addr;
}

static void *set_tags_dc(void *addr, size_t size, uint8_t tag)
{
	return set_tags_dc_helper(memtag_insert_tag(addr, tag), size);
}

static void *set_random_tags_dc(void *addr, size_t size)
{
	return set_tags_dc_helper(insert_random_tag(addr), size);
}

static void *set_tags(void *addr, size_t size, uint8_t tag)
{
	return set_tags_helper(memtag_insert_tag(addr, tag), size);
}

static void *set_random_tags(void *addr, size_t size)
{
	return set_tags_helper(insert_random_tag(addr), size);
}

static void clear_mem(void *va, size_t size)
{
	set_tags(va, size, 0);
	memset(memtag_strip_tag(va), 0, size);
}

static void clear_mem_dc(void *addr, size_t size)
{
	size_t dcsz = dczid_block_size();
	vaddr_t va = (vaddr_t)addr;
	size_t mask = dcsz - 1;
	size_t s = 0;

	if (va & mask) {
		s = MIN(dcsz - (va & mask), size);
		clear_mem((void *)va, s);
		va += s;
		size -= s;
	}
	s = size & ~mask;
	if (s) {
		clear_mem_dc_gzva(va, s, dcsz);
		va += s;
		size -= s;
	}
	if (size)
		clear_mem((void *)va, size);
}

static uint8_t read_tag(const void *addr)
{
	return memtag_get_tag(load_tag((void *)addr));
}

static const struct __memtag_ops ops_dc_enabled = {
	.set_tags = set_tags_dc,
	.set_random_tags = set_random_tags_dc,
	.clear_mem = clear_mem_dc,
	.read_tag = read_tag,
};

static const struct __memtag_ops ops_enabled = {
	.set_tags = set_tags,
	.set_random_tags = set_random_tags,
	.clear_mem = clear_mem,
	.read_tag = read_tag,
};

const struct __memtag_ops __memtag_ops_disabled = {
	.set_tags = __memtag_disabled_set_tags,
	.set_random_tags = __memtag_disabled_set_random_tags,
	.clear_mem = __memtag_disabled_clear_mem,
	.read_tag = __memtag_disabled_read_tag,
};

const struct __memtag_ops *__memtag_ops = &__memtag_ops_disabled;

void memtag_init_ops(unsigned int memtag_impl)
{
	if (memtag_impl >= 2) {
		/*
		 * Data zero is always available for S-EL1 if MTE is
		 * enabled, but for S-EL0 it may depend on configuration.
		 */
		if (data_zero_prohibited())
			__memtag_ops = &ops_enabled;
		else
			__memtag_ops = &ops_dc_enabled;
	} else {
		__memtag_ops = &__memtag_ops_disabled;
	}
}
#endif
