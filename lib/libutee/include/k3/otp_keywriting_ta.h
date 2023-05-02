/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Texas Instruments System Control Interface Driver
 *
 * Copyright (C) 2023 Texas Instruments Incorporated - https://www.ti.com/
 *	Manorit Chawdhry <m-chawdhry@ti.com>
 */

#ifndef __K3_OTP_KEYWRITING_TA_H__
#define __K3_OTP_KEYWRITING_TA_H__

/* UUID of the trusted application */
#define PTA_K3_OTP_KEYWRITING_UUID \
	{ 0xacc50f40, 0x0613, 0x4abd, \
		{ 0x8d, 0xfe, 0xa9, 0x64, 0xcb, 0x74, 0xeb, 0x69} }

#define PTA_K3_OTP_KEYWRITING_NAME "pta_k3_otp.ta"

/*
 * TA_OTP_KEYWRITING_CMD_READ_MMR - Read an extended OTP bit
 * param[0] (value/input)  32-bit MMR index
 * param[1] (value/output) OTP value written in efuse
 * param[2] unused
 * param[3] unused
 */
#define TA_OTP_KEYWRITING_CMD_READ_MMR		0

/*
 * TA_OTP_KEYWRITING_CMD_WRITE_ROW - Write into extended OTP row
 * param[0] (value/input) Row index
 * param[1].a (value/input) Value to be written
 * param[1].b (value/input) Mask for the value
 * param[2] unused
 * param[3] unused
 */
#define TA_OTP_KEYWRITING_CMD_WRITE_ROW		1

/*
 * TA_OTP_KEYWRITING_CMD_LOCK_ROW - Lock an extended OTP row
 * param[0].a (value/input) Row index
 * param[0].b (value/input)
 *	BIT(0) - soft_lock
 *	BIT(1) - hw_read_lock
 *	BIT(2) - hw_write_lock
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_OTP_KEYWRITING_CMD_LOCK_ROW		2

#define K3_OTP_KEYWRITING_SOFT_LOCK		BIT(0)
#define K3_OTP_KEYWRITING_HW_READ_LOCK		BIT(1)
#define K3_OTP_KEYWRITING_HW_WRITE_LOCK		BIT(2)

#endif /* __K3_OTP_KEYWRITING_TA_H__ */
