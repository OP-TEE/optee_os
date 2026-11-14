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

struct tme_fuse_write_row_msg {
	uint32_t status;
	struct tme_fuse_payload fuse;
};

struct tme_fuse_write_multiple_rows_msg {
	uint32_t status;
	uint32_t p_buffer;
	uint32_t buf_len;
};

struct tme_oem_mrc_state_update_msg {
	uint32_t activate_vector;
	uint32_t revocate_vector;
	uint32_t status;
};

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

TEE_Result tme_fuse_write_row(const struct tme_fuse_payload *fuse)
{
	struct tme_fuse_write_row_msg msg = { };
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!fuse)
		return TEE_ERROR_BAD_PARAMETERS;

	msg.status = TME_STATUS_UNKNOWN;
	msg.fuse = *fuse;

	ret = tme_fuse_send(TME_MSG_UID_FUSE_WRITE_SINGLE_ROW,
			    TME_MSG_UID_FUSE_WRITE_SINGLE_ROW_PARAM_ID,
			    &msg, sizeof(msg), &msg.status);
	memzero_explicit(&msg, sizeof(msg));

	return ret;
}

TEE_Result tme_fuse_write_multiple_rows(const struct tme_fuse_payload *fuse,
					size_t num_rows)
{
	struct tme_fuse_write_multiple_rows_msg msg = { };
	struct tme_fuse_payload *buf = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;
	paddr_t paddr = 0;
	size_t size = 0;

	if (!fuse || !num_rows ||
	    MUL_OVERFLOW(num_rows, sizeof(*fuse), &size))
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

	memcpy(buf, fuse, size);

	msg.status = TME_STATUS_UNKNOWN;
	msg.p_buffer = (uint32_t)paddr;
	msg.buf_len = size;

	ret = tme_fuse_send(TME_MSG_UID_FUSE_WRITE_MULTIPLE_ROW,
			    TME_MSG_UID_FUSE_WRITE_MULTIPLE_ROW_PARAM_ID,
			    &msg, sizeof(msg), &msg.status);

out_release:
	tmecom_client_release_buf();
	return ret;
}

TEE_Result tme_oem_mrc_state_update(uint32_t activate_vector,
				    uint32_t revocate_vector)
{
	struct tme_oem_mrc_state_update_msg msg = { };

	msg.activate_vector = activate_vector;
	msg.revocate_vector = revocate_vector;
	msg.status = TME_STATUS_UNKNOWN;

	return tme_fuse_send(TME_MSG_UID_SECBOOT_OEM_MRC_STATE_UPDATE,
			     TME_MSG_UID_SECBOOT_OEM_MRC_STATE_UPDATE_PARAM_ID,
			     &msg, sizeof(msg), &msg.status);
}
