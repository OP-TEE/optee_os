/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019, 2021 NXP
 *
 * Brief   Specific Macro used to read/write value with a specific
 *         format (BE/LE, 32/64 bits) to be updated for future platform
 *         support.
 */

#ifndef __CAAM_IO_H__
#define __CAAM_IO_H__

#include <io.h>

#ifdef CFG_CAAM_BIG_ENDIAN
/* Big Endian 32 bits Registers access */
#define io_caam_read32(a)	TEE_U32_FROM_BIG_ENDIAN(io_read32(a))
#define io_caam_write32(a, val) io_write32(a, TEE_U32_TO_BIG_ENDIAN(val))

/* Big Endian 32 bits Value access */
#define caam_read_val32(a)	get_be32(a)
#define caam_write_val32(a, v)	put_be32(a, v)
#else
/* Little Endian 32 bits Registers access */
#define io_caam_read32(a)	io_read32(a)
#define io_caam_write32(a, val) io_write32(a, val)

/* Little Endian 32 bits Value access */
#define caam_read_val32(a)	get_le32(a)
#define caam_write_val32(a, v)	put_le32(a, v)

#define caam_read_val64(a)     get_le64(a)
#define caam_write_val64(a, v) put_le64(a, v)
#endif

#endif /* __CAAM_IO_H__ */
