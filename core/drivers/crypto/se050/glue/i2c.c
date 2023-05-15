// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <compiler.h>
#include <config.h>
#include <glue.h>
#include <i2c_native.h>
#include <initcall.h>
#include <kernel/rpc_io_i2c.h>
#include <phNxpEsePal_i2c.h>

static TEE_Result (*transfer)(struct rpc_i2c_request *req, size_t *bytes);

static int i2c_transfer(uint8_t *buffer, int len, enum rpc_i2c_mode mode)
{
	struct rpc_i2c_request request = {
		.bus = CFG_CORE_SE05X_I2C_BUS,
		.chip = SMCOM_I2C_ADDRESS >> 1,
		.mode = mode,
		.buffer = buffer,
		.buffer_len = len,
		.flags = 0,
	};
	size_t bytes = 0;
	int retry = 5;

	do {
		if ((*transfer)(&request, &bytes) == TEE_SUCCESS)
			return bytes;
	} while (--retry);

	return -1;
}

int glue_i2c_read(uint8_t *buffer, int len)
{
	return i2c_transfer(buffer, len, RPC_I2C_MODE_READ);
}

int glue_i2c_write(uint8_t *buffer, int len)
{
	return i2c_transfer(buffer, len, RPC_I2C_MODE_WRITE);
}

int glue_i2c_init(void)
{
	if (transfer == rpc_io_i2c_transfer)
		return 0;

	transfer = native_i2c_transfer;

	return native_i2c_init();
}

static TEE_Result load_trampoline(void)
{
	if (IS_ENABLED(CFG_CORE_SE05X_I2C_TRAMPOLINE))
		transfer = rpc_io_i2c_transfer;

	return TEE_SUCCESS;
}

boot_final(load_trampoline);
