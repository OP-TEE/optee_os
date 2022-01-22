// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <drivers/imx_i2c.h>
#include <i2c_native.h>
#include <phNxpEsePal_i2c.h>

TEE_Result native_i2c_transfer(struct rpc_i2c_request *req,
			       size_t *bytes)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (req->mode == RPC_I2C_MODE_READ)
		ret = imx_i2c_read(req->bus, req->chip, req->buffer,
				   req->buffer_len);
	else
		ret = imx_i2c_write(req->bus, req->chip, req->buffer,
				    req->buffer_len);

	if (!ret)
		*bytes = req->buffer_len;

	return ret;
}

int native_i2c_init(void)
{
	if (imx_i2c_init(CFG_CORE_SE05X_I2C_BUS, CFG_CORE_SE05X_BAUDRATE))
		return -1;

	if (imx_i2c_probe(CFG_CORE_SE05X_I2C_BUS, SMCOM_I2C_ADDRESS >> 1))
		return -1;

	return 0;
}
