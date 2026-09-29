/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_HAL_H__
#define __QFPROM_HAL_H__

#include <drivers/qcom/qfprom/qfprom.h>
#include <stdbool.h>
#include <stdint.h>

void hal_qfprom_set_blow_timer(uint32_t value);
void hal_qfprom_set_accel(uint32_t value);
enum qfprom_error hal_qfprom_read_raw_address(uint32_t addr, uint32_t *value);
enum qfprom_error hal_qfprom_read_raw_address_row(uint32_t addr,
						  uint32_t *value);
enum qfprom_error hal_qfprom_write_raw_address(uint32_t addr, uint32_t value);
enum qfprom_error hal_qfprom_read_corrected_address(uint32_t addr,
						    uint32_t *value);
enum qfprom_error hal_qfprom_read_corrected_address_row(uint32_t addr,
							uint32_t *value);
enum qfprom_error hal_qfprom_read_blow_status(uint32_t *value);
void hal_qfprom_clear_fec_error_status(void);
bool hal_qfprom_is_fec_error_seen(void);
void hal_qfprom_read_error_address(uint16_t *value);

#endif /* __QFPROM_HAL_H__ */
