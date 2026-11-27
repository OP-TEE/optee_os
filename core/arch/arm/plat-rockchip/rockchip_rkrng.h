/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Rockchip RKRNG register definitions (RK3576/RK3562/RK3528).
 * Used by both the driver (rockchip_rkrng.c) and the early platform
 * canary override (platform_rk3576.c).
 */

#ifndef ROCKCHIP_RKRNG_H
#define ROCKCHIP_RKRNG_H

#include <io.h>
#include <types_ext.h>
#include <util.h>

#define RKRNG_CTRL			0x0010
#define RKRNG_CTRL_REQ_TRNG		BIT(4)
#define RKRNG_STATE			0x0014
#define RKRNG_STATE_TRNG_RDY		BIT(4)
#define RKRNG_TRNG_DATA0		0x0050

/* One request yields 8 x 32-bit words = 256 bits */
#define RKRNG_READ_WORDS		8
#define RKRNG_READ_LEN			(RKRNG_READ_WORDS * sizeof(uint32_t))

#define RKRNG_POLL_TIMEOUT_US		10000

/*
 * The data window is Device memory. Read it a word at a time with
 * io_read32() instead of memcpy(), which is free to emit unaligned or
 * multi-register accesses that Device memory does not guarantee.
 */
static inline void rkrng_read_data(vaddr_t base, uint32_t *buf)
{
	unsigned int i = 0;

	for (i = 0; i < RKRNG_READ_WORDS; i++)
		buf[i] = io_read32(base + RKRNG_TRNG_DATA0 + i * 4);
}

#endif /* ROCKCHIP_RKRNG_H */
