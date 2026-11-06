// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tmecom_client.h>
#include <tmefuse_client.h>
#include <tmemessages_uids.h>
#include <trace.h>
#include <types_ext.h>
#include <util.h>

/* Send a fuse request and map the status in the reply, @status, to a result */
static TEE_Result tme_fuse_send(uint32_t uid, uint32_t param_id, void *msg,
				uint32_t len, const uint32_t *status)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	ret = tmecom_client_send_message(uid, param_id, true,
					 TMECOM_DEFAULT_TIMEOUT, msg, len,
					 NULL, NULL, NULL);
	if (ret != TEE_SUCCESS) {
		EMSG("TME fuse IPC 0x%x failed: 0x%x", uid, ret);
		return ret;
	}

	ret = tme_status_to_tee_result(*status);
	if (ret != TEE_SUCCESS)
		EMSG("TME fuse request 0x%x failed, status: 0x%x", uid,
		     *status);

	return ret;
}

TEE_Result tme_fuse_write_row(const struct tme_fuse_row *row)
{
	struct tme_fuse_write_row_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!row)
		return TEE_ERROR_BAD_PARAMETERS;

	msg.status = TME_STATUS_UNKNOWN;
	msg.row = *row;

	ret = tme_fuse_send(TME_MSG_UID_FUSE_WRITE_SINGLE_ROW,
			    TME_MSG_UID_FUSE_WRITE_SINGLE_ROW_PARAM_ID,
			    &msg, sizeof(msg), &msg.status);
	/* The row may be key material */
	memzero_explicit(&msg, sizeof(msg));

	return ret;
}

TEE_Result tme_fuse_write_rows(const struct tme_fuse_row *rows, size_t count)
{
	struct tme_fuse_write_rows_msg msg = { };
	struct tme_fuse_row *buf = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
	paddr_t paddr = 0;
	size_t size = 0;

	if (!rows || !count || MUL_OVERFLOW(count, sizeof(*rows), &size))
		return TEE_ERROR_BAD_PARAMETERS;

	buf = tmecom_client_get_coherent_buf(size, &paddr);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	if (paddr + size - 1 > UINT32_MAX) {
		EMSG("Fuse rows buffer paddr %#"PRIxPA" exceeds 32-bit range",
		     paddr);
		ret = TEE_ERROR_GENERIC;
		goto out_release;
	}

	memcpy(buf, rows, size);

	msg.status = TME_STATUS_UNKNOWN;
	msg.rows = (uint32_t)paddr;
	msg.rows_len = size;

	ret = tme_fuse_send(TME_MSG_UID_FUSE_WRITE_MULTIPLE_ROW,
			    TME_MSG_UID_FUSE_WRITE_MULTIPLE_ROW_PARAM_ID,
			    &msg, sizeof(msg), &msg.status);

out_release:
	tmecom_client_release_buf();
	return ret;
}

TEE_Result tme_fuse_update_oem_mrc(uint32_t activate, uint32_t revoke)
{
	struct tme_fuse_oem_mrc_msg msg = { };

	msg.activate = activate;
	msg.revoke = revoke;
	msg.status = TME_STATUS_UNKNOWN;

	return tme_fuse_send(TME_MSG_UID_SECBOOT_OEM_MRC_STATE_UPDATE,
			     TME_MSG_UID_SECBOOT_OEM_MRC_STATE_UPDATE_PARAM_ID,
			     &msg, sizeof(msg), &msg.status);
}
