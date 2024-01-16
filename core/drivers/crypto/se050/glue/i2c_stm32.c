// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <assert.h>
#include <drivers/pinctrl.h>
#include <drivers/stm32_i2c.h>
#include <i2c_native.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <phNxpEsePal_i2c.h>

static_assert(CFG_CORE_SE05X_I2C_BUS < 10);
static struct i2c_handle_s i2c;

TEE_Result native_i2c_transfer(struct rpc_i2c_request *req, size_t *bytes)
{
	if (req->mode == RPC_I2C_MODE_READ) {
		if (stm32_i2c_master_receive(&i2c, req->chip << 1, req->buffer,
					     req->buffer_len, 25))
			return TEE_ERROR_GENERIC;
	} else {
		if (stm32_i2c_master_transmit(&i2c, req->chip << 1, req->buffer,
					      req->buffer_len, 25))
			return TEE_ERROR_GENERIC;
	}

	*bytes = req->buffer_len;

	return TEE_SUCCESS;
}

static int dt_i2c_bus_config(struct stm32_i2c_init_s *init,
			     struct pinctrl_state **pinctrl_active,
			     struct pinctrl_state **pinctrl_sleep)
{
	const fdt32_t *cuint = NULL;
	const char *path = NULL;
	char bus[6] = { };
	void *fdt = NULL;
	int node = 0;

	fdt = get_embedded_dt();
	if (!fdt)
		return -FDT_ERR_NOTFOUND;

	snprintf(bus, sizeof(bus), "i2c%d", CFG_CORE_SE05X_I2C_BUS);

	path = fdt_get_alias(fdt, bus);
	if (!path)
		return -FDT_ERR_NOTFOUND;

	node = fdt_path_offset(fdt, path);
	if (node < 0)
		return -FDT_ERR_NOTFOUND;

	cuint = fdt_getprop(fdt, node, "clock-frequency", NULL);
	if (cuint && fdt32_to_cpu(*cuint) != CFG_CORE_SE05X_BAUDRATE)
		IMSG("SE05X ignoring CFG_CORE_SE05X_BAUDRATE, use DTB");
	else if (I2C_STANDARD_RATE != CFG_CORE_SE05X_BAUDRATE)
		IMSG("SE05x ignoring CFG_CORE_SE05X_BAUDRATE, use built-in");

	return stm32_i2c_get_setup_from_fdt(fdt, node, init, pinctrl_active,
					    pinctrl_sleep);
}

int native_i2c_init(void)
{
	struct stm32_i2c_init_s i2c_init = { };

	/* No need to re-initialize */
	if (i2c.base.pa)
		return 0;

	/* Support only one device on the platform */
	if (dt_i2c_bus_config(&i2c_init, &i2c.pinctrl, &i2c.pinctrl_sleep))
		return -1;

	/* Probe the device */
	i2c_init.own_address1 = SMCOM_I2C_ADDRESS;
	i2c_init.digital_filter_coef = 0;
	i2c_init.analog_filter = true;

	stm32_i2c_resume(&i2c);

	return stm32_i2c_init(&i2c, &i2c_init);
}
