/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, ProvenRun SAS
 */

#ifndef __PTA_VERSAL_LOADER_H
#define __PTA_VERSAL_LOADER_H

#define PTA_VERSAL_LOADER_UUID { 0xa6b493c0, 0xe100, 0x4a13, \
	{ 0x9b, 0x00, 0xbc, 0xe4, 0x2d, 0x53, 0xce, 0xd8 } }

/**
 * Load subsystem PDI
 *
 * [in]		memref[0]	Subsystem PDI buffer
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_OUT_OF_MEMORY - Could not alloc internal buffer
 */
#define PTA_VERSAL_LOADER_SUBSYS	0x0

 #endif /* __PTA_VERSAL_LOADER_H */
