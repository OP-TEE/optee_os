// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <compiler.h>
#include <drivers/imx_i2c.h>
#include <initcall.h>
#include <kernel/rpc_io_i2c.h>
#include <phEseStatus.h>
#include <phNxpEsePal_i2c.h>

static TEE_Result (*transfer)(struct rpc_i2c_request *req, size_t *bytes);

static TEE_Result native_i2c_transfer(struct rpc_i2c_request *req,
				      size_t *bytes)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (req->mode == RPC_I2C_MODE_READ)
		ret = imx_i2c_read(req->bus, req->chip, req->buffer,
				   req->buffer_len);
	else
		ret = imx_i2c_write(req->bus, req->chip, req->buffer,
				    req->buffer_len);

	*bytes = req->buffer_len;

	return ret;
}

static int i2c_transfer(uint8_t *buffer, int len, enum rpc_i2c_mode mode)
{
	struct rpc_i2c_request request = {
		.bus = CFG_CORE_SE05X_I2C_BUS,
		.chip = SMCOM_I2C_ADDRESS >> 1,
		.mode = mode,
		.buffer = buffer,
		.buffer_len = len,
		.flags = 0,
		.retries = 20,
	};
	size_t bytes = 0;
	int retry = 5;

	do {
		if ((*transfer)(&request, &bytes) == TEE_SUCCESS)
			return bytes;
	} while (--retry && (transfer != &rpc_io_i2c_transfer));

	return -1;
}

void phPalEse_i2c_close(void *handle __unused)
{
}

int phPalEse_i2c_read(void *foo __unused, uint8_t *buffer, int len)
{
	return i2c_transfer(buffer, len, RPC_I2C_MODE_READ);
}

int phPalEse_i2c_write(void *foo __unused, uint8_t *buffer, int len)
{
	return i2c_transfer(buffer, len, RPC_I2C_MODE_WRITE);
}

ESESTATUS phPalEse_i2c_open_and_configure(pphPalEse_Config_t pConfig __unused)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	/* once the trampoline has been loaded, keep it running */
	if (transfer == &rpc_io_i2c_transfer)
		return ESESTATUS_SUCCESS;

	/* start with the native OP-TEE driver */
	transfer = &native_i2c_transfer;

	ret = imx_i2c_init(CFG_CORE_SE05X_I2C_BUS, CFG_CORE_SE05X_BAUDRATE);
	if (ret != TEE_SUCCESS)
		return ESESTATUS_INVALID_DEVICE;

	ret = imx_i2c_probe(CFG_CORE_SE05X_I2C_BUS, SMCOM_I2C_ADDRESS >> 1);
	if (ret != TEE_SUCCESS)
		return ESESTATUS_INVALID_DEVICE;

	return ESESTATUS_SUCCESS;
}

static TEE_Result load_trampoline(void)
{
	/* switch to the trampoline driver on OP-TEE boot done */
	transfer = &rpc_io_i2c_transfer;

	return TEE_SUCCESS;
}

driver_init_late(load_trampoline);
