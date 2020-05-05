/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2019, Linaro Limited
 */

/*
 * Enumerate the pseudo TAs that have the TA_FLAG_DEVICE_ENUM flag enabled.
 */

#ifndef __PTA_DEVICE_H
#define __PTA_DEVICE_H

#define PTA_DEVICE_UUID { 0x7011a688, 0xddde, 0x4053, \
		{ 0xa5, 0xa9, 0x7b, 0x3c, 0x4d, 0xdf, 0x13, 0xb8 } }

/*
 * Get device UUIDs
 *
 * [out]     memref[0]        Array of device UUIDs
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_CMD_GET_DEVICES		0x0 /* before tee-supplicant run */
#define PTA_CMD_GET_DEVICES_SUPP	0x1 /* after tee-supplicant run */

#endif /* __PTA_DEVICE_H */
