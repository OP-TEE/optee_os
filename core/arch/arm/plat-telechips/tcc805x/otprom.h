/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#ifndef TCC805X_OTPROM_H
#define TCC805X_OTPROM_H

#include <util.h>

#define OTPROM_MAX			U(0x4000)
#define OTPROM_128_START		U(0x1000)
#define OTPROM_128_LIMIT		U(0x2000)

/* HUK */
#define OTP_DATA_TEE_HUK_OFFSET		U(0x1ED0)
#define OTP_DATA_TEE_HUK_SIZE		U(0x10)

#endif /* TCC805X_OTPROM_H */
