// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 Microchip
 */

#include <drivers/i2c.h>
#include <kernel/dt.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <malloc.h>
#include <tee_api_types.h>
#include <trace.h>
#include <types_ext.h>
#include <tee_api_defines_extensions.h>

SLIST_HEAD(ctrl_list, i2c_ctrl);
static struct ctrl_list ctrl_list = SLIST_HEAD_INITIALIZER(ctrl_list);

static struct i2c_ctrl *i2c_ctrl_get_by_node(int node)
{
	struct i2c_ctrl *i2c_ctrl = NULL;

	SLIST_FOREACH(i2c_ctrl, &ctrl_list, link) {
		if (i2c_ctrl->node == node)
			return i2c_ctrl;
	}

	return NULL;
}

static struct i2c_dev *i2c_create_dev(struct i2c_ctrl *i2c_ctrl,
				      const void *fdt, int node)
{
	struct i2c_dev *i2c_dev = NULL;
	paddr_t addr = _fdt_reg_base_address(fdt, node);

	i2c_dev = calloc(1, sizeof(struct i2c_dev *));
	if (!i2c_dev)
		return NULL;

	i2c_dev->addr = addr;
	i2c_dev->ctrl = i2c_ctrl;

	return i2c_dev;
}

TEE_Result __i2c_probe(const void *fdt, int node, const void *compat_data,
		       const struct dt_driver *dt_drv)
{
	int parent = -1;
	struct i2c_ctrl *i2c_ctrl = NULL;
	struct i2c_dev *i2c_dev = NULL;
	const struct i2c_driver *i2c_drv = NULL;

	parent = fdt_parent_offset(fdt, node);
	if (parent < 0)
		return TEE_ERROR_BAD_FORMAT;

	i2c_ctrl = i2c_ctrl_get_by_node(parent);
	if (!i2c_ctrl)
		return TEE_ERROR_BAD_STATE;

	i2c_dev = i2c_create_dev(i2c_ctrl, fdt, node);
	if (!i2c_dev)
		return TEE_ERROR_OUT_OF_MEMORY;

	i2c_drv = dt_drv->driver;

	return i2c_drv->probe(i2c_dev, fdt, node, compat_data);
}

TEE_Result i2c_ctrl_register(struct i2c_ctrl *i2c_ctrl, const void *fdt,
			     int node)
{
	i2c_ctrl->node = node;
	SLIST_INSERT_HEAD(&ctrl_list, i2c_ctrl, link);

	dt_driver_probe_node(fdt, node);

	return TEE_SUCCESS;
}
