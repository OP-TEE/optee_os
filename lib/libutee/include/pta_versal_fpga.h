/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2023, ProvenRun SAS
 */

#ifndef __PTA_VERSAL_FPGA_H
#define __PTA_VERSAL_FPGA_H

#define PTA_VERSAL_FPGA_UUID { 0xa6b493c0, 0xe100, 0x4a13, \
	{ 0x9b, 0x00, 0xbc, 0xe4, 0x2d, 0x53, 0xce, 0xd8 } }

/**
 * Write FPGA bitstream
 *
 * [in]		memref[0]	FPGA bitstream buffer
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_OUT_OF_MEMORY - Could not alloc internal buffer
 */
#define PTA_VERSAL_FPGA_WRITE		0x0

 #endif /* __PTA_VERSAL_FPGA_H */
