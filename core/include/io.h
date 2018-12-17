/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */
#ifndef IO_H
#define IO_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>
#include <utee_defines.h>

/*
 * Make sure that compiler reads given variable only once. This is needed
 * in cases when we have normal shared memory, and this memory can be changed
 * at any moment. Compiler does not knows about this, so it can optimize memory
 * access in any way, including repeated read from the same address. This macro
 * enforces compiler to access memory only once.
 */
#define READ_ONCE(p) __compiler_atomic_load(&(p))

static inline void write8(uint8_t val, vaddr_t addr)
{
	*(volatile uint8_t *)addr = val;
}

static inline void write16(uint16_t val, vaddr_t addr)
{
	*(volatile uint16_t *)addr = val;
}

static inline void write32(uint32_t val, vaddr_t addr)
{
	*(volatile uint32_t *)addr = val;
}

static inline uint8_t read8(vaddr_t addr)
{
	return *(volatile uint8_t *)addr;
}

static inline uint16_t read16(vaddr_t addr)
{
	return *(volatile uint16_t *)addr;
}

static inline uint32_t read32(vaddr_t addr)
{
	return *(volatile uint32_t *)addr;
}

static inline void io_mask8(vaddr_t addr, uint8_t val, uint8_t mask)
{
	write8((read8(addr) & ~mask) | (val & mask), addr);
}

static inline void io_mask16(vaddr_t addr, uint16_t val, uint16_t mask)
{
	write16((read16(addr) & ~mask) | (val & mask), addr);
}

static inline void io_mask32(vaddr_t addr, uint32_t val, uint32_t mask)
{
	write32((read32(addr) & ~mask) | (val & mask), addr);
}

static inline uint64_t get_be64(const void *p)
{
	return TEE_U64_FROM_BIG_ENDIAN(*(const uint64_t *)p);
}

static inline void put_be64(void *p, uint64_t val)
{
	*(uint64_t *)p = TEE_U64_TO_BIG_ENDIAN(val);
}

static inline uint32_t get_be32(const void *p)
{
	return TEE_U32_FROM_BIG_ENDIAN(*(const uint32_t *)p);
}

static inline void put_be32(void *p, uint32_t val)
{
	*(uint32_t *)p = TEE_U32_TO_BIG_ENDIAN(val);
}

static inline uint16_t get_be16(const void *p)
{
	return TEE_U16_FROM_BIG_ENDIAN(*(const uint16_t *)p);
}

static inline void put_be16(void *p, uint16_t val)
{
	*(uint16_t *)p = TEE_U16_TO_BIG_ENDIAN(val);
}

/*
 * Set and clear bits helpers.
 *
 * @addr is the address of the memory cell accessed
 * @set_mask represents the bit mask of the bit(s) to set, aka set to 1
 * @clear_mask represents the bit mask of the bit(s) to clear, aka reset to 0
 *
 * io_clrsetbits32() clears then sets the target bits in this order. If a bit
 * position is defined by both @set_mask and @clear_mask, the bit will be set.
 */
static inline void io_setbits32(uintptr_t addr, uint32_t set_mask)
{
	write32(read32(addr) | set_mask, addr);
}

static inline void io_clrbits32(uintptr_t addr, uint32_t clear_mask)
{
	write32(read32(addr) & ~clear_mask, addr);
}

static inline void io_clrsetbits32(uintptr_t addr, uint32_t clear_mask,
				   uint32_t set_mask)
{
	write32((read32(addr) & ~clear_mask) | set_mask, addr);
}

#endif /*IO_H*/
