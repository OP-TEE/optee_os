//SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017 - 2018, ARM Limited
 */

#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <mm/tee_mmu.h>
#include <sdp_pta.h>

#define PTA_NAME "sdp.pta"

static TEE_Result sdp_pa_cmd_virt_to_phys(uint32_t types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	char *va = params[0].memref.buffer;
	size_t len = params[0].memref.size;
	struct tee_ta_session *s;
	struct user_ta_ctx *utc;
	TEE_Result res;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters types: 0x%" PRIx32, types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	s = tee_ta_get_calling_session();
	if (!s)
		return TEE_ERROR_ACCESS_DENIED;

	utc = to_user_ta_ctx(s->ctx);
	res = tee_mmu_check_access_rights(utc, TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  (uaddr_t)va, len);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_ACCESS_DENIED;

	if (!core_vbuf_is(CORE_MEM_SDP_MEM, va, len)) {
		DMSG("bad memref secure attribute");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reg_pair_from_64(virt_to_phys(va), &params[1].value.a,
			 &params[1].value.b);

	return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */
static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext __unused)
{
	struct tee_ta_session *s = tee_ta_get_calling_session();

	if (s && (s->ctx->flags & TA_FLAG_SECURE_DATA_PATH)) {
		DMSG("open entry point for pseudo-TA \"%s\"", PTA_NAME);
		return TEE_SUCCESS;
	}

	DMSG("TA %pUl is unauthorised access to pseudo-TA \"%s\"",
	     (void *)&s->ctx->uuid, PTA_NAME);

	return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result invoke_command(void *pSessionContext __unused,
				 uint32_t nCommandID, uint32_t nParamTypes,
				 TEE_Param pParams[TEE_NUM_PARAMS])
{
	FMSG("command entry point for pseudo-TA \"%s\"", PTA_NAME);

	switch (nCommandID) {
	case PTA_CMD_SDP_VIRT_TO_PHYS:
		return sdp_pa_cmd_virt_to_phys(nParamTypes, pParams);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_SDP_PTA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_SECURE_DATA_PATH,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
