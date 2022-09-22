// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <drivers/bcm/bnxt.h>
#include <io.h>
#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <util.h>

#define BNXT_SERVICE_UUID \
		{0x6272636D, 0x2019, 0x0716,  \
		{0x42, 0x43, 0x4D, 0x5F, 0x53, 0x43, 0x48, 0x49} }

/*
 * enum pta_bnxt_cmd - commands supported by this PTA
 * PTA_BNXT_FASTBOOT:		boot bnxt device by copying f/w into sram
 *
 * PTA_BNXT_HEALTH_STATUS:	check health of bnxt device
 *					[out] value[0].a - health status
 *
 * PTA_BNXT_HANDSHAKE_STATUS:	check bnxt device is booted
 *					[inout] value[0].a - max timeout value
 *						value[0].a - boot status
 *
 * PTA_BNXT_CRASH_DUMP_COPY:	copy the core dump into shm
 *					[inout] memref[0].buf: destination addr
 *					[in] value[1].a: offset
 *					[in] value[1].b: size
 */
enum pta_bnxt_cmd {
	PTA_BNXT_FASTBOOT = 0,
	PTA_BNXT_HEALTH_STATUS,
	PTA_BNXT_HANDSHAKE_STATUS,
	PTA_BNXT_CRASH_DUMP_COPY,
	PTA_BNXT_NITRO_HOT_PATCH_INIT,
	PTA_BNXT_NITRO_HOT_PATCH_DEINIT,
	PTA_BNXT_UPDATE_NITRO_HOT_PATCH,
	PTA_BNXT_APPLY_NITRO_HOT_PATCH
};

#define BNXT_TA_NAME		"pta_bnxt.ta"

static TEE_Result get_bnxt_status(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	if (type != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				    TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	p[0].value.a = bnxt_health_status();

	return TEE_SUCCESS;
}

static TEE_Result get_bnxt_handshake_status(uint32_t type,
					    TEE_Param p[TEE_NUM_PARAMS])
{
	if (type != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				    TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	p[0].value.a = bnxt_wait_handshake(p[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result copy_bnxt_crash_dump(uint32_t types,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t *d = NULL;
	uint32_t offset = 0;
	uint32_t req_len = 0;
	TEE_Result res = TEE_SUCCESS;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		DMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	d = (uint32_t *)params[0].memref.buffer;
	offset = params[1].value.a;
	req_len = params[1].value.b;

	if (!d || params[0].memref.size < req_len)
		return TEE_ERROR_BAD_PARAMETERS;

	res = bnxt_copy_crash_dump((uint8_t *)d, offset, req_len);

	return res;
}

/**
 * hot_patch_init() - TEE command to initialize the nitro hot patch driver.
 * @types:	Expected TEE_Param types.
 * @params:	Parameters to use for hot patch initialization.
 *
 * Return:	TEE_Success or > 0 on error.
 */
static TEE_Result hot_patch_init(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("Bad parameter types: 0x%"PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return nitro_hot_patch_init((paddr_t)params[0].value.a,
				    params[0].value.b);
}

/**
 * hot_patch_deinit() - TEE command to reset the nitro hot patch driver.
 * @types:	Expected TEE_Param types.
 * @params:	Unused.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
static TEE_Result hot_patch_deinit(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("Bad parameter types: 0x%"PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return nitro_hot_patch_deinit();
}

/**
 * func_name - TEE command to update the nitro hot patch with.
 * @types:	Expected TEE_Param types.
 * @__unused:	Parameters for shared memory to update the hot patch with.
 *
 * Return:	TEE_SUCCESS or > 0 on error.
 */
static TEE_Result update_hot_patch(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		DMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return update_nitro_hot_patch(params[0].memref.buffer,
				      params[0].memref.size);
}

/**
 * apply_hot_patch() - TEE command to verify and flash a nitro hot patch in
 *		       staging memory.
 * @types:	Expected TEE_Param types.
 * @params:	Unused.
 *
 * Return:	TEE_Success or > 0 on error.
 */
static TEE_Result apply_hot_patch(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("Bad parameter types: 0x%"PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return apply_nitro_hot_patch;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id,
				 uint32_t param_types __unused,
				 TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, BNXT_TA_NAME);

	switch (cmd_id) {
	case PTA_BNXT_FASTBOOT:
		DMSG("bnxt fastboot");
		if (bnxt_load_fw(1) != BNXT_SUCCESS)
			return TEE_ERROR_TARGET_DEAD;
		break;

	case PTA_BNXT_HEALTH_STATUS:
		DMSG("bnxt health status");
		return get_bnxt_status(param_types, params);

	case PTA_BNXT_HANDSHAKE_STATUS:
		DMSG("bnxt handshake status");
		return get_bnxt_handshake_status(param_types, params);

	case PTA_BNXT_CRASH_DUMP_COPY:
		DMSG("bnxt copy crash dump data");
		return copy_bnxt_crash_dump(param_types, params);

	case PTA_BNXT_NITRO_HOT_PATCH_INIT:
		if (IS_ENABLED(CFG_BCM_NITRO_HOT_PATCH))
			return hot_patch_init(param_types, params);
		DMSG("cmd: %d Not supported %s", cmd_id, BNXT_TA_NAME);
		return TEE_ERROR_NOT_SUPPORTED;

	case PTA_BNXT_NITRO_HOT_PATCH_DEINIT:
		if (IS_ENABLED(CFG_BCM_NITRO_HOT_PATCH))
			return hot_patch_deinit(param_types, params);
		DMSG("cmd: %d Not supported %s", cmd_id, BNXT_TA_NAME);
		return TEE_ERROR_NOT_SUPPORTED;

	case PTA_BNXT_UPDATE_NITRO_HOT_PATCH:
		if (IS_ENABLED(CFG_BCM_NITRO_HOT_PATCH))
			return update_hot_patch(param_types, params);
		DMSG("cmd: %d Not supported %s", cmd_id, BNXT_TA_NAME);
		return TEE_ERROR_NOT_SUPPORTED;

	case PTA_BNXT_APPLY_NITRO_HOT_PATCH:
		if (IS_ENABLED(CFG_BCM_NITRO_HOT_PATCH))
			return apply_hot_patch_cmd(param_types, params);
		DMSG("cmd: %d Not supported %s", cmd_id, BNXT_TA_NAME);
		return TEE_ERROR_NOT_SUPPORTED;

	default:
		DMSG("cmd: %d Not supported %s", cmd_id, BNXT_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = BNXT_SERVICE_UUID,
		   .name = BNXT_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
