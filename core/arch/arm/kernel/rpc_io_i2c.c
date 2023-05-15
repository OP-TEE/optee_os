// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 Foundries Ltd <jorge@foundries.io>
 */
#include <kernel/rpc_io_i2c.h>
#include <kernel/thread.h>
#include <mm/mobj.h>
#include <string.h>

/*
 * @brief: I2C master transfer request to an I2C slave device.
 * It is the responsibility of the caller to validate the number of bytes
 * processed by the REE.
 *
 * @param req: the secure world I2C master request
 * @param len: the number of bytes processed by REE
 * @returns: TEE_SUCCESS on success, TEE_ERROR_XXX on error.
 */
TEE_Result rpc_io_i2c_transfer(struct rpc_i2c_request *req, size_t *len)
{
	struct thread_param p[4] = { };
	TEE_Result res = TEE_SUCCESS;
	struct mobj *mobj = NULL;
	uint8_t *va = NULL;

	assert(req);

	if (!len)
		return TEE_ERROR_BAD_PARAMETERS;

	va = thread_rpc_shm_cache_alloc(THREAD_SHM_CACHE_USER_I2C,
					THREAD_SHM_TYPE_KERNEL_PRIVATE,
					req->buffer_len, &mobj);
	if (!va)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (req->mode == RPC_I2C_MODE_WRITE)
		memcpy(va, req->buffer, req->buffer_len);

	p[0] = THREAD_PARAM_VALUE(IN, req->mode, req->bus, req->chip);
	p[1] = THREAD_PARAM_VALUE(IN, req->flags, 0, 0);
	p[2] = THREAD_PARAM_MEMREF(INOUT, mobj, 0, req->buffer_len);
	p[3] = THREAD_PARAM_VALUE(OUT, 0, 0, 0);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_I2C_TRANSFER, ARRAY_SIZE(p), p);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * Reporting more bytes than supplied or requested from the I2C chip is
	 * an REE error
	 */
	if (p[3].u.value.a > req->buffer_len)
		return TEE_ERROR_EXCESS_DATA;

	*len = p[3].u.value.a;

	if (req->mode == RPC_I2C_MODE_READ)
		memcpy(req->buffer, va, *len);

	return TEE_SUCCESS;
}
