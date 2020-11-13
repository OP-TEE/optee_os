/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Schneider Electric
 * Copyright (c) 2020, Linaro Limited
 */

#ifndef RZN1_REGAUTH_H
#define RZN1_REGAUTH_H

struct regauth_t {
	uint32_t paddr;
	uint32_t size;
	uint32_t rmask;
	uint32_t wmask;
};

static const struct regauth_t regauth[] = {
	/* OTP */
	{ 0x40007000U, 0x4U, 0x0U, 0x0U },                /* OTPWCTRL */
	/* System Controller */
	{ 0x4000C064U, 0x4U, 0xFFFFFFFFU, 0xFFFFFFE0U },  /* PWRCTRL_DDRC */
	{ 0x4000C204U, 0x4U, 0x0U, 0x0U },                /* BOOTADDR */
	/* DDR CTRL */
	{ 0x4000D16CU, 0x3FCU, 0x0U, 0x0U },              /* DDR_CTL 91-346 */
	{ 0x4000E000U, 0x4U, 0xFFFFFFFFU, 0xFFFFFFFEU },  /* UNCCTRL */
	{ 0x4000E004U, 0x4U, 0xFFFFFFFFU, 0xFFFFFFFEU },  /* DLLCTRL */
};

#endif /* RZN1_REGAUTH_H */
