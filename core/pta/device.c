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
#include <kernel/stmm_sp.h>
#include <kernel/tee_ta_manager.h>
#include <pta_device.h>
#include <tee/tee_fs.h>
#include <tee/uuid.h>
#include <user_ta_header.h>

#define PTA_NAME "device.pta"

static void add_ta(uint32_t flags, const TEE_UUID *uuid, uint8_t *buf,
		   uint32_t blen, uint32_t *pos, uint32_t rflags)
{
	flags &= (TA_FLAG_DEVICE_ENUM | TA_FLAG_DEVICE_ENUM_SUPP |
		  TA_FLAG_DEVICE_ENUM_TEE_STORAGE_PRIVATE);
	if (flags && flags != TA_FLAG_DEVICE_ENUM &&
	    flags != TA_FLAG_DEVICE_ENUM_SUPP &&
	    flags != TA_FLAG_DEVICE_ENUM_TEE_STORAGE_PRIVATE) {
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

	if (stmm_get_uuid())
		add_ta(TA_FLAG_DEVICE_ENUM_SUPP, stmm_get_uuid(), buf, blen,
		       &pos, rflags);

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
	TEE_Result res = TEE_SUCCESS;
	uint32_t rflags = 0;
	/*
	 * This should also be true if CFG_RPMB_ANNOUNCE_PROBE_CAP is
	 * enabled when the kernel does not support OP-TEE RPMB operations.
	 */
	bool rpmb_needs_supp = !IS_ENABLED(CFG_RPMB_ANNOUNCE_PROBE_CAP);

	switch (nCommandID) {
	case PTA_CMD_GET_DEVICES:
		rflags = TA_FLAG_DEVICE_ENUM;
		break;
	case PTA_CMD_GET_DEVICES_SUPP:
		rflags = TA_FLAG_DEVICE_ENUM_SUPP;
		if (IS_ENABLED(CFG_REE_FS) ||
		    (IS_ENABLED(CFG_RPMB_FS) && rpmb_needs_supp))
			rflags |= TA_FLAG_DEVICE_ENUM_TEE_STORAGE_PRIVATE;
		break;
	case PTA_CMD_GET_DEVICES_RPMB:
		if (!IS_ENABLED(CFG_REE_FS)) {
			res = tee_rpmb_reinit();
			if (res)
				return TEE_ERROR_STORAGE_NOT_AVAILABLE;
			rflags = TA_FLAG_DEVICE_ENUM_TEE_STORAGE_PRIVATE;
		}
		break;
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}

	return get_devices(nParamTypes, pParams, rflags);
}

pseudo_ta_register(.uuid = PTA_DEVICE_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
