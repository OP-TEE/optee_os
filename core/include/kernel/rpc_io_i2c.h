/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020 Foundries Ltd <jorge@foundries.io>
 */

#ifndef __RPC_IO_I2C_H
#define __RPC_IO_I2C_H

#include <tee_api_types.h>

enum rpc_i2c_mode {
	RPC_I2C_MODE_WRITE = 0,
	RPC_I2C_MODE_READ = 1,
};

/*
 * The bus identifier defines an implicit ABI with the REE.
 * Using this service to access i2c chips on REE dynamically assigned buses is
 * not recommended due to the lack of guarantees that the REE will reuse the
 * same bus identifier over reboots.
 */
struct rpc_i2c_request {
	enum rpc_i2c_mode mode;
	uint8_t bus; /* bus identifier used by the REE [0..n] */
	uint8_t chip; /* chip identifier from the device data sheet [0..0x7f] */
	uint8_t *buffer;
	size_t buffer_len;
};

TEE_Result rpc_io_i2c_transfer(struct rpc_i2c_request *p, size_t *bytes);

#endif /* __RPC_IO_I2C_H */
