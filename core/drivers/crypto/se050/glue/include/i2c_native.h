/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef I2C_NATIVE_H_
#define I2C_NATIVE_H_

#include <kernel/rpc_io_i2c.h>

#ifdef CFG_CORE_SE05X_I2C_TRAMPOLINE_ONLY
static inline TEE_Result
native_i2c_transfer(struct rpc_i2c_request *req __unused,
		    size_t *bytes __unused)
{
	/* Stub only */
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline int native_i2c_init(void)
{
	/* Stub only */
	return 0;
}
#else
TEE_Result native_i2c_transfer(struct rpc_i2c_request *req,
			       size_t *bytes);
int native_i2c_init(void);
#endif

#endif
