/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __QFPROM_PRIV_H__
#define __QFPROM_PRIV_H__

#include <drivers/qcom/qfprom/qfprom.h>
#include <qfprom_target.h>
#include <mm/core_mmu.h>

#define QFPROM_BLOW_TIMEOUT_US		1000
#define QFPROM_FEC_REGION_LSB_MAX	32
#define QFPROM_FEC_REGION_MSB_MAX	64

enum qfprom_fec_scheme {
	QFPROM_FEC_NONE = 0,
	QFPROM_FEC_15_10,
	QFPROM_FEC_63_56,
	QFPROM_MAX_FEC
};

enum qfprom_row_type {
	QFPROM_ROW_LSB = 0,
	QFPROM_ROW_MSB,
};

struct qfprom_region_info {
	enum qfprom_region_name region_name;
	uint32_t size;
	enum qfprom_fec_scheme fec_type;
	uint32_t raw_base_addr;
	uint32_t corr_base_addr;
	uint32_t read_perm_mask;
	uint32_t write_perm_mask;
	enum qfprom_row_type perm_reg_type;
	bool read_allowed;
	uint32_t region_index;
};

struct qfprom_platform_config {
	const char *name;
	paddr_t qfprom_raw_base;
	paddr_t qfprom_corr_base;
	size_t qfprom_size;
	uint32_t default_bus_clk_khz;
	const struct qfprom_region_info *region_data;
	size_t num_regions;
	uint32_t read_perm_lsb_offset;
	uint32_t write_perm_lsb_offset;
	uint32_t read_perm_msb_offset;
	uint32_t write_perm_msb_offset;
};

struct qfprom_context {
	const struct qfprom_platform_config *config;
	vaddr_t raw_base_va;
	vaddr_t corr_base_va;
	vaddr_t mutex_reg_va;
	bool write_op_allowed;
};

enum region_permission {
	REGION_PERM_READ  = BIT(0),
	REGION_PERM_WRITE = BIT(1),
};

struct qfprom_context *qfprom_get_context(void);

TEE_Result qfprom_write_set_clock_settings(void);
TEE_Result qfprom_write_reset_clock_settings(void);

TEE_Result qfprom_enable_voltage(void);
TEE_Result qfprom_disable_voltage(void);

TEE_Result qfprom_acquire_hw_mutex(void);
TEE_Result qfprom_release_hw_mutex(void);

const struct qfprom_platform_config *qfprom_get_platform_config(void);

#endif /* __QFPROM_PRIV_H__ */
