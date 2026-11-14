// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <platform_config.h>
#include <stdbool.h>
#include <tee_api_types.h>
#include <tmecom_client.h>
#include <tmel_auth.h>
#include <tmemessages_uids.h>
#include <trace.h>
#include <util.h>

/* Set per SoC in target_config.h; other values fail at run time */
#ifndef TMEL_AUTH_VERSION
#define TMEL_AUTH_VERSION	0
#endif

/* Wire layout of TME_MSG_UID_SECBOOT_SEC_AUTH_PARAM_ID */
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

/* Wire layout of TME_MSG_UID_SECBOOT_SEC_AUTH_V2_PARAM_ID */
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

/*
 * Convert @buf to a TME-Lite descriptor, which holds a 32-bit address and
 * length. An unset buffer, { 0, 0 }, is only valid when @optional.
 */
static TEE_Result tmel_auth_buf_to_desc(const struct tmel_auth_buf *buf,
					bool optional,
					struct tmel_buf_desc *desc)
{
	paddr_t end = 0;

	desc->buf = 0;
	desc->buf_len = 0;

	if (!buf->pa && !buf->len)
		return optional ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS;

	if (!buf->pa || !buf->len || ADD_OVERFLOW(buf->pa, buf->len, &end) ||
	    end > BIT64(32))
		return TEE_ERROR_BAD_PARAMETERS;

	desc->buf = (uint32_t)buf->pa;
	desc->buf_len = (uint32_t)buf->len;

	return TEE_SUCCESS;
}

/*
 * @req is copied by the IPC layer, so it needs no cache maintenance. The
 * buffers it points to are read by TME-Lite directly (see tmel_auth.h).
 */
static TEE_Result tmel_auth_v1(struct tmel_sec_auth_params *params,
			       const struct tmel_buf_desc *elf_buf,
			       const struct tmel_buf_desc *region_list)
{
	struct tmel_sec_auth_v1_req req = {
		.sw_id = params->sw_id,
		.elf_buf = *elf_buf,
		.region_list = *region_list,
		.relocate = params->relocate,
		.status = TME_STATUS_UNKNOWN,
	};
	const uint32_t param_id = TME_MSG_UID_SECBOOT_SEC_AUTH_PARAM_ID;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (sizeof(req) != TMEL_SEC_AUTH_V1_REQ_SIZE) {
		EMSG("Unexpected TME-Lite SEC_AUTH request size %zu",
		     sizeof(req));
		return TEE_ERROR_BAD_FORMAT;
	}

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

static TEE_Result tmel_auth_v2(struct tmel_sec_auth_params *params,
			       const struct tmel_buf_desc *elf_buf,
			       const struct tmel_buf_desc *region_list)
{
	struct tmel_sec_auth_v2_req req = {
		.sw_id = params->sw_id,
		.elf_buf = *elf_buf,
		.region_list = *region_list,
		.relocate = params->relocate,
		.flags = params->flags,
		.status = TME_STATUS_UNKNOWN,
	};
	const uint32_t param_id = TME_MSG_UID_SECBOOT_SEC_AUTH_V2_PARAM_ID;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (sizeof(req) != TMEL_SEC_AUTH_V2_REQ_SIZE) {
		EMSG("Unexpected TME-Lite SEC_AUTH_V2 request size %zu",
		     sizeof(req));
		return TEE_ERROR_BAD_FORMAT;
	}

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
	struct tmel_buf_desc region_list = { };
	struct tmel_buf_desc elf_buf = { };
	TEE_Result res = TEE_ERROR_GENERIC;

	if (!params) {
		EMSG("Invalid authentication parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = tmel_auth_buf_to_desc(&params->elf_buf, false, &elf_buf);
	if (res) {
		EMSG("Invalid ELF buffer");
		return res;
	}

	res = tmel_auth_buf_to_desc(&params->region_list, true, &region_list);
	if (res) {
		EMSG("Invalid region list buffer");
		return res;
	}

	/* Never leave stale results behind for a failed request */
	params->first_seg_addr = 0;
	params->first_seg_len = 0;
	params->entry_addr = 0;
	params->extended_error = 0;
	params->status = TME_STATUS_UNKNOWN;
	params->key_handle = 0;

	switch (TMEL_AUTH_VERSION) {
	case 1:
		res = tmel_auth_v1(params, &elf_buf, &region_list);
		break;
	case 2:
		res = tmel_auth_v2(params, &elf_buf, &region_list);
		break;
	default:
		EMSG("Unsupported TME-Lite auth version %d", TMEL_AUTH_VERSION);
		return TEE_ERROR_NOT_SUPPORTED;
	}
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
