/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025, Pengutronix, Michael Tretter <entwicklung@pengutronix.de>
 */

#ifndef __PTA_RK_SECURE_BOOT_H
#define __PTA_RK_SECURE_BOOT_H

#include <tee_api_types.h>

#define PTA_RK_SECURE_BOOT_UUID { 0x5cfa57f6, 0x1a4c, 0x407f, \
	{ 0x94, 0xa7, 0xa5, 0x6c, 0x8c, 0x47, 0x01, 0x9d } }

struct pta_rk_secure_boot_hash {
	/* sha256 has 256 bit */
	uint8_t value[32];
};

struct pta_rk_secure_boot_info {
	uint8_t enabled;
	uint8_t simulation;
	struct pta_rk_secure_boot_hash hash;
};

/*
 * PTA_RK_SECURE_BOOT_GET_INFO - Get secure boot status info
 *
 * [out]    memref[0]   buffer memory reference containing a struct
 *                      pta_rk_secure_boot_info
 */
#define PTA_RK_SECURE_BOOT_GET_INFO		0x0

/*
 * PTA_RK_SECURE_BOOT_BURN_HASH - Burn the RSA key hash to fuses
 *
 * [in]    memref[0]   buffer memory reference containing a struct
 *                     pta_rk_secure_boot_hash
 * [in]    value[1].a  bit length of signing key
 */
#define PTA_RK_SECURE_BOOT_BURN_HASH		0x1

/*
 * PTA_RK_SECURE_BOOT_LOCKDOWN_DEVICE - Lockdown the device with secure boot
 */
#define PTA_RK_SECURE_BOOT_LOCKDOWN_DEVICE	0x2

#endif /* __PTA_ROCKCHIP_OTP_H */
