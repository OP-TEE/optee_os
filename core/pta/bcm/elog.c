// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm/bnxt.h>
#include <io.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <trace.h>

#define ELOG_SERVICE_UUID \
		{ 0x6272636D, 0x2019, 0x0701, \
		{ 0x42, 0x43, 0x4D, 0x5F, 0x45, 0x4C, 0x4F, 0x47 } }

#define ELOG_TA_NAME			"pta_bcm_elog.ta"

#define BCM_NITRO_FW_LOAD_ADDR			0x8ae00000
#define BCM_NITRO_CRASH_DUMP_BASE_ADDR		0x8b000000

/* Default ELOG buffer size 1MB */
#define DEFAULT_ELOG_BUFFER_SIZE		0x100000U

/*
 * Get Error log memory dump
 *
 * [out]    memref[0]:    Destination
 * [in]     value[1].a:   Offset
 */
#define PTA_BCM_ELOG_CMD_GET_ELOG_MEM		1

/*
 * Get nitro crash_dump memory
 *
 * [out]    memref[0]:    Destination
 * [in]     value[1].a:   Offset
 */
#define PTA_BCM_ELOG_CMD_GET_NITRO_CRASH_DUMP	2

/*
 * Load nitro firmware memory
 *
 * [in]     memref[0]:    Nitro f/w image data
 * [in]     value[1].a:   Offset for loading f/w image
 * [in]     value[2].a:   Firmware image size
 */
#define PTA_BCM_ELOG_CMD_LOAD_NITRO_FW		3

#define BCM_ELOG_GLOBAL_METADATA_SIG		0x45524c47

#define MAX_NITRO_CRASH_DUMP_MEM_SIZE		0x2000000
#define MAX_NITRO_FW_LOAD_MEM_SIZE		0x200000

/* Load Nitro fw image to SEC DDR memory */
static TEE_Result pta_elog_load_nitro_fw(uint32_t param_types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t src_paddr = BCM_NITRO_FW_LOAD_ADDR + BNXT_IMG_SECMEM_OFFSET;
	vaddr_t src_vaddr = 0;
	uint32_t offset = 0, sz = 0;
	char *buf = NULL;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Check if firmware file size exceeds reserved memory size */
	if (params[2].value.a > MAX_NITRO_FW_LOAD_MEM_SIZE) {
		EMSG("Invalid access");
		return TEE_ERROR_EXCESS_DATA;
	}

	offset = params[1].value.a;

	/*
	 * Check if offset is within memory range reserved for nitro firmware
	 * minus default size of buffer
	 */
	if (offset > MAX_NITRO_FW_LOAD_MEM_SIZE - DEFAULT_ELOG_BUFFER_SIZE) {
		EMSG("Invalid access");
		return TEE_ERROR_ACCESS_DENIED;
	}

	buf = params[0].memref.buffer;
	sz = params[0].memref.size;

	src_vaddr = (vaddr_t)phys_to_virt((uintptr_t)src_paddr + offset,
					  MEM_AREA_RAM_SEC, sz);
	if (!src_vaddr) {
		EMSG("Not enough memory mapped");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memcpy((char *)src_vaddr, buf, sz);

	cache_op_inner(DCACHE_AREA_CLEAN, (void *)src_vaddr, sz);

	return res;
}

static uint32_t get_dump_data(vaddr_t src, TEE_Param params[TEE_NUM_PARAMS])
{
	char *buf = NULL;
	uint32_t sz = 0;

	buf = params[0].memref.buffer;
	sz = params[0].memref.size;

	/*
	 * If request size exceeds default buf size
	 * override request size to default DEFAULT_ELOG_BUFFER_SIZE
	 */
	if (sz > DEFAULT_ELOG_BUFFER_SIZE)
		sz = DEFAULT_ELOG_BUFFER_SIZE;

	DMSG("buf %p sz 0x%x", buf, sz);

	memcpy(buf, (char *)src, sz);

	params[0].memref.size = sz;

	return sz;
}

/* Copy nitro crash dump data */
static TEE_Result pta_elog_nitro_crash_dump(uint32_t param_types,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t src_paddr = BCM_NITRO_CRASH_DUMP_BASE_ADDR;
	vaddr_t src_vaddr = 0;
	uint32_t offset = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	uint32_t sz = 0;

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	offset = params[1].value.a;

	/*
	 * Check if offset is within memory range reserved for nitro crash dump
	 * minus default size of buffer
	 */
	if (offset > MAX_NITRO_CRASH_DUMP_MEM_SIZE - DEFAULT_ELOG_BUFFER_SIZE) {
		EMSG("Invalid access");
		return TEE_ERROR_ACCESS_DENIED;
	}

	sz = MIN(params[0].memref.size, DEFAULT_ELOG_BUFFER_SIZE);
	src_vaddr = (vaddr_t)phys_to_virt((uintptr_t)src_paddr + offset,
					  MEM_AREA_RAM_SEC, sz);
	if (!src_vaddr) {
		EMSG("Not enough memory mapped");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* TODO : check if NITRO_CRASH_DUMP is available */

	cache_op_inner(DCACHE_AREA_INVALIDATE, (void *)src_vaddr,
		       DEFAULT_ELOG_BUFFER_SIZE);

	get_dump_data(src_vaddr, params);

	return res;
}

/* Copy soc error log data */
static TEE_Result pta_elog_dump(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	paddr_t src_paddr = CFG_BCM_ELOG_BASE;
	vaddr_t src_vaddr = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	uint32_t sz = 0;

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	sz = MIN(params[0].memref.size, DEFAULT_ELOG_BUFFER_SIZE);
	src_vaddr = (vaddr_t)phys_to_virt(src_paddr, MEM_AREA_RAM_NSEC, sz);
	if (!src_vaddr) {
		EMSG("Not enough memory mapped");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Validate if Error logs are present */
	if ((*(uint32_t *)src_vaddr) != BCM_ELOG_GLOBAL_METADATA_SIG) {
		EMSG("Elog Not setup");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	get_dump_data(src_vaddr, params);

	return res;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, ELOG_TA_NAME);

	switch (cmd_id) {
	case PTA_BCM_ELOG_CMD_GET_ELOG_MEM:
		res = pta_elog_dump(param_types, params);
		break;
	case PTA_BCM_ELOG_CMD_GET_NITRO_CRASH_DUMP:
		res = pta_elog_nitro_crash_dump(param_types, params);
		break;
	case PTA_BCM_ELOG_CMD_LOAD_NITRO_FW:
		res = pta_elog_load_nitro_fw(param_types, params);
		break;
	default:
		EMSG("cmd: %d Not supported %s", cmd_id, ELOG_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = ELOG_SERVICE_UUID,
		   .name = ELOG_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
