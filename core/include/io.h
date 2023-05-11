/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */
#ifndef IO_H
#define IO_H

#include <compiler.h>
#include <stdint.h>
#include <types_ext.h>
#include <utee_defines.h>

/*
 * Make sure that compiler reads/writes given variable only once. This is needed
 * in cases when we have normal shared memory, and this memory can be changed
 * at any moment. Compiler does not knows about this, so it can optimize memory
 * access in any way, including repeated accesses from the same address.
 * These macro enforce compiler to access memory only once.
 */
#define READ_ONCE(p)		__compiler_atomic_load(&(p))
#define WRITE_ONCE(p, v)	__compiler_atomic_store(&(p), (v))

/*
 *  IO port access primitives
 *  -------------------------
 *
 * Arm A-profile cores don't have special IO access instructions.
 * OP-TEE maps IO memory as device, shareable and bufferable but not cacheable.
 *
 * io_readX(), io_writeX() io_clr/setbitsX() functions do not guarantee
 * that the IO request reached the device in the code order.
 *
 * The barrier version of each function - io_readX_barrier(), io_writeX_barier()
 * and io_clr/setbitsX_barrier() - guarantee that IO access are
 * observable for system (outer shareable):
 * - Make sure the write above is visible
 * - Make sure the read is performed
 */
#define __rmb()		dsb()
#define __wmb()		dsb()

static inline void io_write8(vaddr_t addr, uint8_t val)
{
	*(volatile uint8_t *)addr = val;
}

static inline void io_write16(vaddr_t addr, uint16_t val)
{
	*(volatile uint16_t *)addr = val;
}

static inline void io_write32(vaddr_t addr, uint32_t val)
{
	*(volatile uint32_t *)addr = val;
}

static inline void io_write64(vaddr_t addr, uint64_t val)
{
	*(volatile uint64_t *)addr = val;
}

#define io_write8_barrier(v, c)		({ __wmb(); io_write8(v, c); })
#define io_write16_barrier(v, c)	({ __wmb(); io_write16(v, c); })
#define io_write32_barrier(v, c)	({ __wmb(); io_write32(v, c); })
#define io_write64_barrier(v, c)	({ __wmb(); io_write64(v, c); })

static inline uint8_t io_read8(vaddr_t addr)
{
	return *(volatile uint8_t *)addr;
}

static inline uint16_t io_read16(vaddr_t addr)
{
	return *(volatile uint16_t *)addr;
}

static inline uint32_t io_read32(vaddr_t addr)
{
	return *(volatile uint32_t *)addr;
}

static inline uint64_t io_read64(vaddr_t addr)
{
	return *(volatile uint64_t *)addr;
}

#define io_read8_barrier(c)	({ uint8_t  __v = io_read8(c); __rmb(); __v; })
#define io_read16_barrier(c)	({ uint16_t __v = io_read16(c); __rmb(); __v; })
#define io_read32_barrier(c)	({ uint32_t __v = io_read32(c); __rmb(); __v; })
#define io_read64_barrier(c)	\
	({ uint64_t __v = io_read64(c); __rmb(); __v; })

static inline void io_mask8(vaddr_t addr, uint8_t val, uint8_t mask)
{
	io_write8(addr, (io_read8(addr) & ~mask) | (val & mask));
}

static inline void io_mask16(vaddr_t addr, uint16_t val, uint16_t mask)
{
	io_write16(addr, (io_read16(addr) & ~mask) | (val & mask));
}

static inline void io_mask32(vaddr_t addr, uint32_t val, uint32_t mask)
{
	io_write32(addr, (io_read32(addr) & ~mask) | (val & mask));
}

#define io_mask8_barrier(v, c, m)	({ __wmb(); io_mask8(v, c, m); })
#define io_mask16_barrier(v, c, m)	({ __wmb(); io_mask16(v, c, m); })
#define io_mask32_barrier(v, c, m)	({ __wmb(); io_mask32(v, c, m); })

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

static inline void put_le32(const void *p, uint32_t val)
{
	 *(uint32_t *)p = val;
}

static inline uint32_t get_le32(const void *p)
{
	return *(const uint32_t *)p;
}

static inline void put_le64(const void *p, uint64_t val)
{
	 *(uint64_t *)p = val;
}

static inline uint64_t get_le64(const void *p)
{
	return *(const uint64_t *)p;
}

/* Unaligned accesses */

struct __unaligned_u16_t { uint16_t x; } __packed;
struct __unaligned_u32_t { uint32_t x; } __packed;
struct __unaligned_u64_t { uint64_t x; } __packed;

static inline uint64_t get_unaligned_be64(const void *p)
{
	const struct __unaligned_u64_t *tmp = p;

	return TEE_U64_FROM_BIG_ENDIAN(tmp->x);
}

static inline void put_unaligned_be64(void *p, uint64_t val)
{
	struct __unaligned_u64_t *tmp = p;

	tmp->x = TEE_U64_TO_BIG_ENDIAN(val);
}

static inline uint32_t get_unaligned_be32(const void *p)
{
	const struct __unaligned_u32_t *tmp = p;

	return TEE_U32_FROM_BIG_ENDIAN(tmp->x);
}

static inline void put_unaligned_be32(void *p, uint32_t val)
{
	struct __unaligned_u32_t *tmp = p;

	tmp->x = TEE_U32_TO_BIG_ENDIAN(val);
}

static inline uint16_t get_unaligned_be16(const void *p)
{
	const struct __unaligned_u16_t *tmp = p;

	return TEE_U16_FROM_BIG_ENDIAN(tmp->x);
}

static inline void put_unaligned_be16(void *p, uint16_t val)
{
	struct __unaligned_u16_t *tmp = p;

	tmp->x = TEE_U16_TO_BIG_ENDIAN(val);
}

static inline void put_unaligned_le64(void *p, uint64_t val)
{
	struct __unaligned_u64_t *tmp = p;

	tmp->x = val;
}

static inline uint64_t get_unaligned_le64(const void *p)
{
	const struct __unaligned_u64_t *tmp = p;

	return tmp->x;
}

static inline void put_unaligned_le32(void *p, uint32_t val)
{
	struct __unaligned_u32_t *tmp = p;

	tmp->x = val;
}

static inline uint32_t get_unaligned_le32(const void *p)
{
	const struct __unaligned_u32_t *tmp = p;

	return tmp->x;
}

static inline void put_unaligned_le16(void *p, uint16_t val)
{
	struct __unaligned_u16_t *tmp = p;

	tmp->x = val;
}

static inline uint16_t get_unaligned_le16(const void *p)
{
	const struct __unaligned_u16_t *tmp = p;

	return tmp->x;
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
static inline void io_setbits32(vaddr_t addr, uint32_t set_mask)
{
	io_write32(addr, io_read32(addr) | set_mask);
}

static inline void io_clrbits32(vaddr_t addr, uint32_t clear_mask)
{
	io_write32(addr, io_read32(addr) & ~clear_mask);
}

static inline void io_clrsetbits32(vaddr_t addr, uint32_t clear_mask,
				   uint32_t set_mask)
{
	io_write32(addr, (io_read32(addr) & ~clear_mask) | set_mask);
}

static inline void io_setbits16(vaddr_t addr, uint16_t set_mask)
{
	io_write16(addr, io_read16(addr) | set_mask);
}

static inline void io_clrbits16(vaddr_t addr, uint16_t clear_mask)
{
	io_write16(addr, io_read16(addr) & ~clear_mask);
}

static inline void io_clrsetbits16(vaddr_t addr, uint16_t clear_mask,
				   uint16_t set_mask)
{
	io_write16(addr, (io_read16(addr) & ~clear_mask) | set_mask);
}

static inline void io_setbits8(vaddr_t addr, uint8_t set_mask)
{
	io_write8(addr, io_read8(addr) | set_mask);
}

static inline void io_clrbits8(vaddr_t addr, uint8_t clear_mask)
{
	io_write8(addr, io_read8(addr) & ~clear_mask);
}

static inline void io_clrsetbits8(vaddr_t addr, uint8_t clear_mask,
				  uint8_t set_mask)
{
	io_write8(addr, (io_read8(addr) & ~clear_mask) | set_mask);
}

#define io_setbits32_barrier(v, s)	({ __wmb(); io_setbits32(v, c); })
#define io_clrbits32_barrier(v, c)	({ __wmb(); io_clrbits32(v, c); })
#define io_clrsetbits32_barrier(v, c, s) \
					({ __wmb(); io_clrsetbits32(v, c, s); })
#define io_setbits16_barrier(v, s)	({ __wmb(); io_setbits16(v, c); })
#define io_clrbits16_barrier(v, c)	({ __wmb(); io_clrbits16(v, c); })
#define io_clrsetbits16_barrier(v, c, s) \
					({ __wmb(); io_clrsetbits16(v, c, s); })
#define io_setbits8_barrier(v, s)	({ __wmb(); io_setbits8(v, c); })
#define io_clrbits8_barrier(v, c)	({ __wmb(); io_clrbits8(v, c); })
#define io_clrsetbits8_barrier(v, c, s)	({ __wmb(); io_clrsetbits8(v, c, s); })

#endif /*IO_H*/
