// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019, Linaro Limited
 */

/*
 * This pseudo TA is used by normal world OS TEE driver to fetch pseudo TA's
 * UUIDs which can act as TEE bus devices.
 */

#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <pta_device.h>
#include <string.h>
#include <tee/uuid.h>
#include <user_ta_header.h>

#define PTA_NAME "device.pta"

static TEE_Result get_devices(uint32_t types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	const struct pseudo_ta_head *ta;
	TEE_UUID *device_uuid = NULL;
	uint8_t uuid_octet[sizeof(TEE_UUID)];
	size_t ip_size, op_size = 0;
	TEE_Result res = TEE_SUCCESS;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[0].memref.buffer && (params[0].memref.size > 0))
		return TEE_ERROR_BAD_PARAMETERS;

	device_uuid = (TEE_UUID *)params[0].memref.buffer;
	ip_size = params[0].memref.size;

	SCATTERED_ARRAY_FOREACH(ta, pseudo_tas, struct pseudo_ta_head) {
		if (ta->flags & TA_FLAG_DEVICE_ENUM) {
			if (ip_size < sizeof(TEE_UUID)) {
				res = TEE_ERROR_SHORT_BUFFER;
			} else {
				tee_uuid_to_octets(uuid_octet, &ta->uuid);
				memcpy(device_uuid, uuid_octet,
				       sizeof(TEE_UUID));
				device_uuid++;
				ip_size -= sizeof(TEE_UUID);
			}
			op_size += sizeof(TEE_UUID);
		}
	}

	params[0].memref.size = op_size;

	return res;
}

static TEE_Result invoke_command(uint32_t session_id __unused,
				 uint32_t command_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (command_id) {
	case PTA_CMD_GET_DEVICES:
		return get_devices(param_types, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_DEVICE_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
