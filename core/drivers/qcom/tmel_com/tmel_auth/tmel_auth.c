// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <platform_config.h>
#include <tee_api_types.h>
#include <tmecom_client.h>
#include <tmel_auth.h>
#include <tmemessages_uids.h>
#include <trace.h>
#include <util.h>

#ifndef TMEL_AUTH_VERSION
#error "TMEL_AUTH_VERSION must be defined by the target configuration"
#endif
_Static_assert(TMEL_AUTH_VERSION == 1 || TMEL_AUTH_VERSION == 2,
	       "TMEL_AUTH_VERSION must be 1 or 2");

/*
 * Wire layout of the SECBOOT_SEC_AUTH request. Must match the parameter
 * descriptor in TME_MSG_UID_SECBOOT_SEC_AUTH_PARAM_ID.
 */
struct tmel_sec_auth_v1_req {
	/* Input */
	uint32_t sw_id;
	struct tmel_buf_desc elf_buf;
	struct tmel_buf_desc region_list;
	uint32_t relocate;

	/* Output */
	uint32_t first_seg_addr;
	uint32_t first_seg_len;
	uint32_t entry_addr;
	uint32_t extended_error;
	uint32_t status;
};

_Static_assert(sizeof(struct tmel_sec_auth_v1_req) == 44,
	       "Unexpected TME-Lite SEC_AUTH request size");

/*
 * Wire layout of the SECBOOT_SEC_AUTH_V2 request. Must match the parameter
 * descriptor in TME_MSG_UID_SECBOOT_SEC_AUTH_V2_PARAM_ID.
 */
struct tmel_sec_auth_v2_req {
	/* Input */
	uint32_t sw_id;
	struct tmel_buf_desc elf_buf;
	struct tmel_buf_desc region_list;
	uint32_t relocate;
	uint32_t flags;
	struct tmel_buf_desc reserved_buf;

	/* Output */
	uint32_t first_seg_addr;
	uint32_t first_seg_len;
	uint32_t entry_addr;
	uint32_t extended_error;
	uint32_t status;
	uint32_t key_handle;
};

_Static_assert(sizeof(struct tmel_sec_auth_v2_req) == 60,
	       "Unexpected TME-Lite SEC_AUTH_V2 request size");

/*
 * The request is copied into the TME-Lite IPC buffer and the response copied
 * back, so @req is only touched by the CPU and needs no cache maintenance.
 */
static TEE_Result tmel_auth_v1(struct tmel_sec_auth_params *params)
{
	struct tmel_sec_auth_v1_req req = {
		.sw_id = params->sw_id,
		.elf_buf = params->elf_buf,
		.region_list = params->region_list,
		.relocate = params->relocate,
		.status = TME_STATUS_UNKNOWN,
	};
	const uint32_t param_id = TME_MSG_UID_SECBOOT_SEC_AUTH_PARAM_ID;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tmecom_client_send_message(TME_MSG_UID_SECBOOT_SEC_AUTH,
					 param_id, true, TMECOM_DEFAULT_TIMEOUT,
					 &req, sizeof(req), NULL, NULL, NULL);
	if (res)
		return res;

	params->first_seg_addr = req.first_seg_addr;
	params->first_seg_len = req.first_seg_len;
	params->entry_addr = req.entry_addr;
	params->extended_error = req.extended_error;
	params->status = req.status;

	return TEE_SUCCESS;
}

static TEE_Result tmel_auth_v2(struct tmel_sec_auth_params *params)
{
	struct tmel_sec_auth_v2_req req = {
		.sw_id = params->sw_id,
		.elf_buf = params->elf_buf,
		.region_list = params->region_list,
		.relocate = params->relocate,
		.flags = params->flags,
		.status = TME_STATUS_UNKNOWN,
	};
	const uint32_t param_id = TME_MSG_UID_SECBOOT_SEC_AUTH_V2_PARAM_ID;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = tmecom_client_send_message(TME_MSG_UID_SECBOOT_SEC_AUTH_V2,
					 param_id, true, TMECOM_DEFAULT_TIMEOUT,
					 &req, sizeof(req), NULL, NULL, NULL);
	if (res)
		return res;

	params->first_seg_addr = req.first_seg_addr;
	params->first_seg_len = req.first_seg_len;
	params->entry_addr = req.entry_addr;
	params->extended_error = req.extended_error;
	params->status = req.status;
	params->key_handle = req.key_handle;

	return TEE_SUCCESS;
}

TEE_Result tmel_secure_auth(struct tmel_sec_auth_params *params)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!params || !params->elf_buf.buf || !params->elf_buf.buf_len) {
		EMSG("Invalid authentication parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Never leave stale results behind for a failed request */
	params->first_seg_addr = 0;
	params->first_seg_len = 0;
	params->entry_addr = 0;
	params->extended_error = 0;
	params->status = TME_STATUS_UNKNOWN;
	params->key_handle = 0;

	if (TMEL_AUTH_VERSION == 2)
		res = tmel_auth_v2(params);
	else
		res = tmel_auth_v1(params);
	if (res) {
		EMSG("TME-Lite auth v%d IPC failed: %#"PRIx32,
		     TMEL_AUTH_VERSION, res);
		return res;
	}

	res = tme_status_to_tee_result(params->status);
	if (res) {
		EMSG("TME-Lite auth v%d: status %#"PRIx32" ext_err %#"PRIx32,
		     TMEL_AUTH_VERSION, params->status, params->extended_error);
		return res;
	}

	if (params->extended_error) {
		EMSG("TME-Lite auth v%d failed: ext_err %#"PRIx32,
		     TMEL_AUTH_VERSION, params->extended_error);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}
