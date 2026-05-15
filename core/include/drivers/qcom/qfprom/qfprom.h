/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_H__
#define __QFPROM_H__

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

enum qfprom_addr_space {
	QFPROM_ADDR_SPACE_RAW = 0,
	QFPROM_ADDR_SPACE_CORR = 1,
};

enum qfprom_error {
	QFPROM_NO_ERR = 0x0,
	QFPROM_ERR_UNKNOWN = 0x1,
	QFPROM_DATA_PTR_NULL_ERR = 0x2,
	QFPROM_ADDRESS_INVALID_ERR = 0x3,
	QFPROM_WRITE_ERR = 0x4,
	QFPROM_REGION_NOT_SUPPORTED_ERR = 0x5,
	QFPROM_REGION_NOT_READABLE_ERR = 0x6,
	QFPROM_REGION_NOT_WRITABLE_ERR = 0x7,
	QFPROM_FEC_ERR = 0x8,
	QFPROM_OPERATION_NOT_ALLOWED_ERR = 0x9,
	QFPROM_FAILED_TO_CHANGE_VOLTAGE_ERR = 0xA,
	QFPROM_ERROR_CLOCK_FAILED = 0x10,
	QFPROM_ERROR_TIMEOUT = 0x11,
};

/* Read QFPROM row data */
TEE_Result qfprom_read_row(uint32_t addr,
			   enum qfprom_addr_space type,
			   uint32_t *data);

/* Write QFPROM row data */
TEE_Result qfprom_write_row(uint32_t addr, uint32_t *data);

/* Check if row has FEC protection */
TEE_Result qfprom_row_has_fec_bits(uint32_t addr,
				   enum qfprom_addr_space type,
				   uint8_t *has_fec);

/* Calculate FEC bits for 56-bit data */
uint32_t qfprom_fec_63_56_bit(uint32_t lsb_data, uint32_t msb_data);

/* Hardware init/deinit for batch fuse operations */
TEE_Result qfprom_hw_init(void);
void qfprom_hw_deinit(void);

#endif /* __QFPROM_H__ */
