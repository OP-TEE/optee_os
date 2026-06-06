/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Rockchip RKRNG register definitions (RK3576/RK3562/RK3528).
 * Used by both the driver (rockchip_rkrng.c) and the early platform
 * canary override (platform_rk3576.c).
 */

#ifndef ROCKCHIP_RKRNG_H
#define ROCKCHIP_RKRNG_H

#define RKRNG_CTRL			0x0010
#define RKRNG_CTRL_REQ_TRNG		BIT(4)
#define RKRNG_STATE			0x0014
#define RKRNG_STATE_TRNG_RDY		BIT(4)
#define RKRNG_TRNG_DATA0		0x0050
#define RKRNG_READ_LEN			32	/* 8 x 32-bit words = 256 bits */

#define RKRNG_POLL_TIMEOUT_US		10000

#endif /* ROCKCHIP_RKRNG_H */
