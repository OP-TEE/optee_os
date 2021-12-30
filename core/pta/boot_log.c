// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 Devendra Devadiga.
 */

#include <io.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trace.h>
#include <bootlog/bootlog.h>
#include <pta_boot_log.h>

static TEE_Result pta_clear_bootlog(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t src_vaddr = 0;
	uint32_t clearLen = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	src_vaddr = (vaddr_t)phys_to_virt(CFG_TEE_BOOT_LOG_START,
			MEM_AREA_IO_SEC, BOOT_LOG_HEADER_SIZE);

	if (!src_vaddr) {
		EMSG("Not enough memory mapped");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memcpy((char *)src_vaddr + BOOT_LOG_CUR_LEN_OFF, (char *)&clearLen,
			BOOT_LOG_CUR_LEN_SIZE);

	return res;
}


static TEE_Result pta_get_boot_log_size(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t src_vaddr = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	src_vaddr = (vaddr_t)phys_to_virt(CFG_TEE_BOOT_LOG_START,
			MEM_AREA_IO_SEC, BOOT_LOG_HEADER_SIZE);

	if (!src_vaddr) {
		EMSG("Not enough memory mapped");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memcpy((char *)&params[0].value.a, (char *)src_vaddr +
			BOOT_LOG_CUR_LEN_OFF, BOOT_LOG_CUR_LEN_SIZE);

	return res;

}

static TEE_Result get_boot_log_message(vaddr_t src,
		TEE_Param params[TEE_NUM_PARAMS])
{
	char *buf = NULL;
	uint32_t len;

	buf = params[0].memref.buffer;

	memcpy((char *)&params[0].memref.size, (char *)src +
			BOOT_LOG_CUR_LEN_OFF, BOOT_LOG_CUR_LEN_SIZE);
	memcpy((char *)&params[0].value.a, (char *)src + BOOT_LOG_CUR_LEN_OFF,
			BOOT_LOG_CUR_LEN_SIZE);

	len = params[0].value.a;

	DMSG("buf %p sz 0x%x", buf, len);

	memcpy(buf, (char *)src + BOOT_LOG_HEADER_SIZE, len);

	return TEE_SUCCESS;
}

/* Copy boot log message */
static TEE_Result pta_get_boot_log(uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	vaddr_t src_vaddr = 0;
	uint32_t map_size;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);
	uint32_t signature = BOOT_LOG_SIG_VAL;
	uint32_t lenInit = 0x0;

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	map_size = MIN(params[0].memref.size, (BOOT_LOG_MAX_SIZE));
	src_vaddr = (vaddr_t)phys_to_virt(CFG_TEE_BOOT_LOG_START,
			MEM_AREA_IO_SEC, (map_size + BOOT_LOG_HEADER_SIZE));

	if (!src_vaddr) {
		EMSG("Not enough memory mapped");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Validate if boot logs are present or not*/
	if ((*(uint32_t *)src_vaddr) != BOOT_LOG_SIG_VAL) {
		DMSG("Elog Not setup: 0x%x", (*(uint32_t *)src_vaddr));
		memcpy((char *)src_vaddr, (char *)&signature,
				BOOT_LOG_SIG_OFFSET_SIZE);
		memcpy((char *)src_vaddr + BOOT_LOG_CUR_LEN_OFF,
				(char *)&lenInit, BOOT_LOG_CUR_LEN_SIZE);
		DMSG("Bootlog setup done by PTA.");
	}

	get_boot_log_message(src_vaddr, params);

	return res;
}

static TEE_Result invoke_command(void *session_context __unused,
		uint32_t cmd_id,
		uint32_t param_types,
		TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, PTA_BOOT_LOG_NAME);

	switch (cmd_id) {
	case PTA_BOOT_LOG_GET_MSG:
		res = pta_get_boot_log(param_types, params);
		break;
	case PTA_BOOT_LOG_GET_SIZE:
		res = pta_get_boot_log_size(param_types, params);
		break;
	case PTA_BOOT_LOG_CLEAR:
		res = pta_clear_bootlog(param_types, params);
		break;
	default:
		EMSG("cmd: %d Not supported %s", cmd_id, PTA_BOOT_LOG_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = BOOT_LOG_SERVICE_UUID,
		.name = PTA_BOOT_LOG_NAME,
		.flags = PTA_DEFAULT_FLAGS,
		.invoke_command_entry_point = invoke_command);
