/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#include <string.h>
#include <trace.h>

#include <initcall.h>
#include <kernel/thread.h>
#include <mm/mobj.h>
#include <mm/tee_mmu_types.h>
#include <optee_rpc_cmd.h>

#include <gcov.h>

/*
 * Write the coverage data to filesystem in the file filepath
 *
 * @filepath      Path of the file to write
 * @cov_data      Coverage data to write
 * @cov_data_size Coverage data size
 */
static TEE_Result tee_gcov_writer(const char *filepath, char *cov_data,
				  uint32_t cov_data_size)
{
	TEE_Result res = TEE_SUCCESS;
	struct thread_param params[2] = {};
	struct mobj *mobj = NULL;
	char *buf = NULL;
	size_t pl_sz = 0;
	uint32_t filepath_size = 0;

	if (!filepath || !cov_data) {
		EMSG("Wrong parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Compute size counting null terminator */
	filepath_size = strlen(filepath) + 1;

	pl_sz = ROUNDUP(filepath_size + cov_data_size, SMALL_PAGE_SIZE);

	mobj = thread_rpc_alloc_payload(pl_sz);
	if (!mobj) {
		EMSG("Gcov thread_rpc_alloc_payload failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	buf = mobj_get_va(mobj, 0);
	if (!buf) {
		EMSG("Can't get pointer on buffer");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	memcpy(buf, filepath, filepath_size);
	memcpy(buf + filepath_size, cov_data, cov_data_size);

	params[0] = THREAD_PARAM_MEMREF(IN, mobj, 0, filepath_size);
	params[1] = THREAD_PARAM_MEMREF(IN, mobj, filepath_size, cov_data_size);

	res = thread_rpc_cmd(OPTEE_RPC_CMD_GCOV, 2, params);
	if (res)
		EMSG("Gcov thread_rpc_cmd res: %#" PRIx32, res);

out:
	thread_rpc_free_payload(mobj);

	return res;
}

/*
 * Register tee_gcov_writer() to gcov library
 */
static TEE_Result register_gcov_write_late(void)
{
	return register_gcov_dump_writer(tee_gcov_writer);
}

service_init_late(register_gcov_write_late);
