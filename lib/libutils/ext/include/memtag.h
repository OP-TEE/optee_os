/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#ifndef __MEMTAG_H
#define __MEMTAG_H

#include <assert.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

#if defined(CFG_MEMTAG) && defined(__aarch64__)
#define MEMTAG_IS_ENABLED	1
#define MEMTAG_TAG_SHIFT	56
#define MEMTAG_TAG_WIDTH	4
#define MEMTAG_TAG_MASK		(BIT(MEMTAG_TAG_WIDTH) - 1)

#define MEMTAG_GRANULE_SIZE	16
#else
#define MEMTAG_IS_ENABLED	0
#define MEMTAG_GRANULE_SIZE	1
#define MEMTAG_TAG_WIDTH	0
#endif

#define MEMTAG_GRANULE_MASK	(MEMTAG_GRANULE_SIZE - 1)

struct __memtag_ops {
	void *(*set_tags)(void *addr, size_t size, uint8_t tag);
	void *(*set_random_tags)(void *addr, size_t size);
	void (*clear_mem)(void *addr, size_t size);
	uint8_t (*read_tag)(const void *addr);
};

extern const struct __memtag_ops __memtag_ops_disabled;
extern const struct __memtag_ops *__memtag_ops;

static inline void *__memtag_disabled_set_tags(void *addr, size_t size __unused,
					       uint8_t tag __unused)
{
	return addr;
}

static inline void *__memtag_disabled_set_random_tags(void *addr,
						      size_t size __unused)
{
	return addr;
}

static inline void __memtag_disabled_clear_mem(void *addr, size_t size)
{
	memset(addr, 0, size);
}

static inline uint8_t __memtag_disabled_read_tag(const void *addr __unused)
{
	return 0;
}

/*
 * memtag_set_tags() - Tag a memory range
 * @addr:	Start of memory range
 * @size:	Size of memory range
 * @tag:	Tag to use
 *
 * The memory range is updated with the supplied tag. An eventual tag
 * already present in the upper bits of the address in @addr is ignored.
 *
 * @addr and @size must be aligned/multiple of MEMTAG_GRANULE_SIZE.
 *
 * Returns an address with the new tag inserted to be used to access this
 * memory area.
 */
static inline void *memtag_set_tags(void *addr, size_t size, uint8_t tag)
{
#if MEMTAG_IS_ENABLED
	return __memtag_ops->set_tags(addr, size, tag);
#else
	return __memtag_disabled_set_tags(addr, size, tag);
#endif
}

/*
 * memtag_set_random_tags() - Tag a memory range with a random tag
 * @addr:	Start of memory range
 * @size:	Size of memory range
 *
 * The memory range is updated with a randomly generated tag. An eventual
 * tag already present in the upper bits of the address in @addr is
 * ignored.
 *
 * @addr and @size must be aligned/multiple of MEMTAG_GRANULE_SIZE.
 *
 * Returns an address with the new tag inserted to be used to access this
 * memory area.
 */
static inline void *memtag_set_random_tags(void *addr, size_t size)
{
#if MEMTAG_IS_ENABLED
	return __memtag_ops->set_random_tags(addr, size);
#else
	return __memtag_disabled_set_random_tags(addr, size);
#endif
}

static inline void memtag_clear_mem(void *addr, size_t size)
{
#if MEMTAG_IS_ENABLED
	__memtag_ops->clear_mem(addr, size);
#else
	__memtag_disabled_clear_mem(addr, size);
#endif
}

/*
 * memtag_strip_tag_vaddr() - Removes an eventual tag from an address
 * @addr:	Address to strip
 *
 * Returns a vaddr_t without an eventual tag.
 */
static inline vaddr_t memtag_strip_tag_vaddr(const void *addr)
{
	vaddr_t va = (vaddr_t)addr;

#if MEMTAG_IS_ENABLED
	va &= ~SHIFT_U64(MEMTAG_TAG_MASK, MEMTAG_TAG_SHIFT);
#endif

	return va;
}

/*
 * memtag_strip_tag_const() - Removes an eventual tag from an address
 * @addr:	Address to strip
 *
 * Returns the address without an eventual tag.
 */
static inline const void *memtag_strip_tag_const(const void *addr)
{
	return (const void *)memtag_strip_tag_vaddr(addr);
}

/*
 * memtag_strip_tag() - Removes an eventual tag from an address
 * @addr:	Address to strip
 *
 * Returns the address without an eventual tag.
 */
static inline void *memtag_strip_tag(void *addr)
{
	return (void *)memtag_strip_tag_vaddr(addr);
}

/*
 * memtag_insert_tag_vaddr() - Inserts a tag into an address
 * @addr:	Address to transform
 * @tag:	Tag to insert
 *
 * Returns the address with the new tag inserted.
 */
static inline vaddr_t memtag_insert_tag_vaddr(vaddr_t addr,
					      uint8_t tag __maybe_unused)
{
	vaddr_t va = memtag_strip_tag_vaddr((void *)addr);

#if MEMTAG_IS_ENABLED
	va |= SHIFT_U64(tag, MEMTAG_TAG_SHIFT);
#endif

	return va;
}

/*
 * memtag_insert_tag() - Inserts a tag into an address
 * @addr:	Address to transform
 * @tag:	Tag to insert
 *
 * Returns the address with the new tag inserted.
 */
static inline void *memtag_insert_tag(void *addr, uint8_t tag)
{
	return (void *)memtag_insert_tag_vaddr((vaddr_t)addr, tag);
}

/*
 * memtag_get_tag() - Extract a tag from an address
 * @addr:	Address with an eventual tag
 *
 * Returns the extracted tag.
 */
static inline uint8_t memtag_get_tag(const void *addr __maybe_unused)
{
#if MEMTAG_IS_ENABLED
	uint64_t va = (vaddr_t)addr;

	return (va >> MEMTAG_TAG_SHIFT) & MEMTAG_TAG_MASK;
#else
	return 0;
#endif
}

static inline uint8_t memtag_read_tag(const void *addr)
{
#if MEMTAG_IS_ENABLED
	return __memtag_ops->read_tag(addr);
#else
	return __memtag_disabled_read_tag(addr);
#endif
}

static inline void memtag_assert_tag(const void *addr __maybe_unused)
{
	assert(memtag_get_tag(addr) == memtag_read_tag(addr));
}

#if MEMTAG_IS_ENABLED
void memtag_init_ops(unsigned int memtag_impl);
#else
static inline void memtag_init_ops(unsigned int memtag_impl __unused)
{
}
#endif

static inline bool memtag_is_enabled(void)
{
#if MEMTAG_IS_ENABLED
	return __memtag_ops != &__memtag_ops_disabled;
#else
	return false;
#endif
}

#endif /*__MEMTAG_H*/
