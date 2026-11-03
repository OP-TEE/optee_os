// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * TME use case: read a QFPROM fuse.
 *
 * The write side lives in tme_fuse_write_multiple.c - read its header before
 * touching it, fuses are one-time-programmable.
 */

#include <drivers/qcom/tme/tme_intf.h>
#include <drivers/qcom/tme/tme_intf_defs.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_types.h>

#include "tme_message.h"
#include "tme_tags.h"

TEE_Result tme_fuse_read(TmeQfpromAddrSpace_t addr_type, uint32_t fuse_addr,
			 uint32_t *const fuse_data,
			 uint32_t *const qfprom_api_status)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	tmeFuseReadReq_t fuse_read_req = { };
	tmeFuseReadRsp_t fuse_read_rsp = { };
	size_t response_len = sizeof(fuse_read_rsp);

	if (!fuse_data || !qfprom_api_status)
		goto bail;

	fuse_read_req.addr_type = (uint32_t)addr_type;
	fuse_read_req.fuse_addr = fuse_addr;

	res = tme_transceive_message(TME_MSG_CBOR_TAG_FUSE_READ,
				     &fuse_read_req, sizeof(fuse_read_req),
				     &fuse_read_rsp, sizeof(fuse_read_rsp),
				     &response_len);
	if (res != TEE_SUCCESS)
		goto bail;

	if (response_len != sizeof(fuse_read_rsp)) {
		res = TEE_ERROR_GENERIC;
		goto bail;
	}

	/*
	 * The caller is required to supply room for the whole row
	 * (TME_QFPROM_FUSE_DATA_WORDS words). Unlike memscpy(), memcpy() copies
	 * the source size without the short copy check, which could never fire.
	 */
	memcpy(fuse_data, fuse_read_rsp.fuse_data,
	       sizeof(fuse_read_rsp.fuse_data));

	*qfprom_api_status = fuse_read_rsp.qfprom_api_status;

	res = TEE_SUCCESS;

bail:
	return res;
}
