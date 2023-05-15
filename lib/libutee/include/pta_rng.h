/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018, Linaro Limited
 */

#ifndef __PTA_RNG_H
#define __PTA_RNG_H

#define PTA_RNG_UUID { 0xab7a617c, 0xb8e7, 0x4d8f, \
		{ 0x83, 0x01, 0xd0, 0x9b, 0x61, 0x03, 0x6b, 0x64 } }

#define TEE_ERROR_HEALTH_TEST_FAIL	0x00000001

/*
 * PTA_CMD_GET_ENTROPY - Get Entropy from RNG using Thermal Sensor
 *
 * [in/out]   memref[0] - Entropy buffer memory reference
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_NOT_SUPPORTED - Requested entropy size greater than size of pool
 * TEE_ERROR_HEALTH_TEST_FAIL - Continuous health testing failed
 */
#define PTA_CMD_GET_ENTROPY		0x0

/*
 * PTA_CMD_GET_RNG_INFO - Get RNG information
 *
 * [out]     value[0].a - RNG data-rate in bytes per second
 * [out]     value[0].b - Quality/Entropy per 1024 bit of data
 * param[1] unused
 * param[2] unused
 * param[3] unused
 *
 * Result:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_GET_RNG_INFO		0x1

#endif /* __PTA_RNG_H */
