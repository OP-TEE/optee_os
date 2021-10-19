/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __PTA_IMX_OCOTP_H__
#define __PTA_IMX_OCOTP_H__

#define PTA_OCOTP_UUID { 0x9abdf255, 0xd8fa, 0x40de, \
	{ 0x8f, 0x60, 0x4d, 0x0b, 0x27, 0x92, 0x7b, 0x7d } }

/**
 * Read chip UID
 *
 * [out]	memref[0].buffer	Output buffer to store UID
 * [out]	memref[0].size		Size of the UID (64 bits)
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input parameter
 * TEE_ERROR_GENERIC - UID not available
 */
#define PTA_OCOTP_CMD_CHIP_UID 0

/*
 * Read chip OTP fuse
 *
 * [in]		params[0].value.a	Fuse bank number
 * [in]		params[0].value.b	Fuse word number
 * [out]	params[1].value.a	Fuse value
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input parameter
 * TEE_ERROR_BUSY - OCOTP not available
 */
#define PTA_OCOTP_CMD_READ_FUSE 1
#endif /* __PTA_IMX_OCOTP_H__ */
