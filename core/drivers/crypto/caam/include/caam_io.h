/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2019 NXP
 *
 * @file    caam_io.h
 *
 * @brief   Specific Macro used to read/write value with a specific
 *          format (BE/LE, 32/64 bits) to be updated for future platform
 *          support.
 */

#ifndef __CAAM_IO_H__
#define __CAAM_IO_H__

#include <io.h>

static inline void put_le32(const void *p, uint32_t val)
{
	 *(uint32_t *)p = val;
}

static inline uint32_t get_le32(const void *p)
{
	return (*(const uint32_t *)p);
}

static inline void put_le64(const void *p, uint32_t val)
{
	 *(uint64_t *)p = val;
}

static inline uint32_t get_le64(const void *p)
{
	return ((uint64_t)get_le32((uintptr_t *)p + 4) << 32) | get_le32(p);
}

#ifdef CFG_CAAM_64BIT
/*
 * CAAM is 64 Bits handling
 */
#ifdef CFG_CAAM_BIG_ENDIAN
/* CAAM is 64 Bits Big Endian */
#define caam_read_val(a)	get_be64(a)
#define caam_write_val(a, v)	put_be64(a, v)
#else
/* CAAM is 64 Bits Little Endian */
#define caam_read_val(a)	get_le64(a)
#define caam_write_val(a, v)	put_le64(a, v)
#endif
#else
/*
 * CAAM is 32 Bits handling
 */
#ifdef CFG_CAAM_BIG_ENDIAN
/* CAAM is 32 Bits Big Endian */
#define caam_read_val(a)	get_be32(a)
#define caam_write_val(a, v)	put_be32(a, v)
#else
/* CAAM is 32 Bits Little Endian */
#define caam_read_val(a)	get_le32(a)
#define caam_write_val(a, v)	put_le32(a, v)
#endif
#endif

#ifdef CFG_CAAM_BIG_ENDIAN
/* CAAM is 32 Bits Big Endian */
#define io_caam_read32(a)	TEE_U32_FROM_BIG_ENDIAN(io_read32(a))
#define io_caam_write32(a, val) io_write32(a, TEE_U32_TO_BIG_ENDIAN(val))
#else
/* CAAM is 32 Bits Little Endian */
#define io_caam_read32(a)	io_read32(a)
#define io_caam_write32(a, val) io_write32(a, val)
#endif


#endif /* __CAAM_IO_H__ */
