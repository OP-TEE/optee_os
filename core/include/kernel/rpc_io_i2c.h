/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020 Foundries Ltd <jorge@foundries.io>
 */

#ifndef __RPC_IO_I2C_H
#define __RPC_IO_I2C_H

#include <optee_rpc_cmd.h>
#include <tee_api_types.h>

/* I2C master transfer mode */
enum rpc_i2c_mode {
	RPC_I2C_MODE_WRITE = OPTEE_RPC_I2C_TRANSFER_WR,
	RPC_I2C_MODE_READ = OPTEE_RPC_I2C_TRANSFER_RD,
};

/* I2C master transfer control flags */
#define RPC_I2C_FLAGS_TEN_BIT	OPTEE_RPC_I2C_FLAGS_TEN_BIT

/*
 * The bus identifier defines an implicit ABI with the REE.
 * Using this service to access I2C slaves on REE dynamically assigned buses is
 * not recommended unless there is a guarantee that the bus identifier will
 * persist across reboots.
 */
struct rpc_i2c_request {
	enum rpc_i2c_mode mode;
	uint16_t bus; /* bus identifier used by the REE [0..n] */
	uint16_t chip; /* slave identifier from its data sheet */
	uint16_t flags; /* transfer flags (ie: ten bit chip address) */
	uint8_t *buffer;
	size_t buffer_len;
};

TEE_Result rpc_io_i2c_transfer(struct rpc_i2c_request *p, size_t *bytes);

#endif /* __RPC_IO_I2C_H */
