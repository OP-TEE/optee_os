/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Telechips Inc.
 */

#ifndef __DRIVERS_OPENEDGES_OMC_H
#define __DRIVERS_OPENEDGES_OMC_H

#include <types_ext.h>
#include <util.h>

#define OMC_FLAG_RELATIVE_ADDR	BIT(0)

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
	uint32_t flags;
};

void omc_init(vaddr_t base, uint32_t size, uint8_t num);
void omc_configure_region(uint8_t region, const struct omc_region_config *cfg);
void omc_set_action(enum omc_action action);

void omc_fail_dump(uint8_t filter);
void omc_int_clear(uint8_t filter);

#endif /* __DRIVERS_OPENEDGES_OMC_H */
