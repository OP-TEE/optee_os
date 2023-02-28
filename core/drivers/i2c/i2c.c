// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 Microchip
 */

#include <drivers/i2c.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <malloc.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>

struct i2c_dev *i2c_create_dev(struct i2c_ctrl *i2c_ctrl, const void *fdt,
			       int node)
{
	struct i2c_dev *i2c_dev = NULL;
	paddr_t addr = fdt_reg_base_address(fdt, node);

	if (addr == DT_INFO_INVALID_REG)
		return NULL;

	i2c_dev = calloc(1, sizeof(struct i2c_dev));
	if (!i2c_dev)
		return NULL;

	i2c_dev->addr = addr;
	i2c_dev->ctrl = i2c_ctrl;

	return i2c_dev;
}
