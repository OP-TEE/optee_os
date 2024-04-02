// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 ProvenRun SAS
 */
#include <drivers/versal_pm.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <pta_versal_fpga.h>
#include <string.h>
#include <tee/cache.h>

#define FPGA_PTA_NAME "fpga.pta"

static TEE_Result pta_versal_fpga_write(uint32_t param_types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *buf;
	size_t bufsize;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	bufsize = ROUNDUP(params[0].memref.size, CACHELINE_LEN);

	buf = memalign(CACHELINE_LEN, bufsize);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(buf, params[0].memref.buffer, bufsize);
	cache_operation(TEE_CACHEFLUSH, buf, bufsize);

	return versal_write_fpga(virt_to_phys(buf));
}

static TEE_Result invoke_command(void *sess_ctx __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_VERSAL_FPGA_WRITE:
		return pta_versal_fpga_write(param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_VERSAL_FPGA_UUID, .name = FPGA_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
