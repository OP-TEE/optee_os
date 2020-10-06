// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Linaro Limited
 */

/*
 * This pseudo TA is used by normal world OS TEE driver to fetch pseudo TA's
 * UUIDs which can act as TEE bus devices.
 */

#include <config.h>
#include <kernel/early_ta.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <pta_device.h>
#include <string.h>
#include <tee/uuid.h>
#include <user_ta_header.h>

#define PTA_NAME "device.pta"

static void add_ta(uint32_t flags, const TEE_UUID *uuid, uint8_t *buf,
		   uint32_t blen, uint32_t *pos, uint32_t rflags)
{
	if ((flags & TA_FLAG_DEVICE_ENUM) &&
	    (flags & TA_FLAG_DEVICE_ENUM_SUPP)) {
		EMSG(PTA_NAME ": skipping TA %pUl, inconsistent flags", uuid);
		return;
	}

	if (flags & rflags) {
		if (*pos + sizeof(*uuid) <= blen)
			tee_uuid_to_octets(buf + *pos, uuid);

		*pos += sizeof(*uuid);
	}
}

static TEE_Result get_devices(uint32_t types,
			      TEE_Param params[TEE_NUM_PARAMS],
			      uint32_t rflags)
{
	const struct pseudo_ta_head *ta = NULL;
	const struct embedded_ts *eta = NULL;
	void *buf = NULL;
	uint32_t blen = 0;
	uint32_t pos = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer && (params[0].memref.size > 0))
		return TEE_ERROR_BAD_PARAMETERS;

	buf =  params[0].memref.buffer;
	blen = params[0].memref.size;

	SCATTERED_ARRAY_FOREACH(ta, pseudo_tas, struct pseudo_ta_head)
		add_ta(ta->flags, &ta->uuid, buf, blen, &pos, rflags);

	if (IS_ENABLED(CFG_EARLY_TA))
		for_each_early_ta(eta)
			add_ta(eta->flags, &eta->uuid, buf, blen, &pos,
			       rflags);

	params[0].memref.size = pos;
	if (pos > blen)
		return TEE_ERROR_SHORT_BUFFER;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	switch (nCommandID) {
	case PTA_CMD_GET_DEVICES:
		return get_devices(nParamTypes, pParams,
				   TA_FLAG_DEVICE_ENUM);
	case PTA_CMD_GET_DEVICES_SUPP:
		return get_devices(nParamTypes, pParams,
				   TA_FLAG_DEVICE_ENUM_SUPP);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_DEVICE_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
