/* SPDX-License-Identifier: (BSD-2-Clause AND BSD-3-Clause) */
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#ifndef __DRIVERS_TCC_OMC_H
#define __DRIVERS_TCC_OMC_H

#include <types_ext.h>

enum omc_action {
	OMC_ACTION_NONE = 0,
	OMC_ACTION_ERR,
	OMC_ACTION_INT,
	OMC_ACTION_ERR_INT
};

struct omc_region_config {
	uint32_t filters;
	uint64_t base;
	uint64_t top;
	uint32_t ns_device_access;
};

void omc_init(vaddr_t base, uint32_t size, uint8_t num);
void omc_configure_region(uint8_t region, const struct omc_region_config *cfg);
void omc_set_action(enum omc_action action);

void omc_fail_dump(uint8_t filter);
void omc_int_clear(uint8_t filter);

#endif /* __DRIVERS_TCC_OMC_H */
