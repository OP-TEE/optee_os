// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * TME use case: QFPROM multi-row fuse write.
 *
 * ###########################################################################
 * # QFPROM FUSES ARE ONE-TIME-PROGRAMMABLE.                                 #
 * #                                                                         #
 * # Every set bit in a TMEFuse_t.data[] word permanently blows that fuse    #
 * # bit on real silicon. It cannot be un-blown, the part cannot be          #
 * # recovered, and blowing the wrong row can brick the device or lock it    #
 * # out of secure boot. An all-zero data[] blows nothing and is the only    #
 * # value that is safe to send speculatively.                               #
 * #                                                                         #
 * # This function does not and cannot validate the caller's intent - TME FW #
 * # will happily program whatever it is handed, subject only to its own     #
 * # region permission checks. The responsibility is entirely at the call    #
 * # site.                                                                   #
 * ###########################################################################
 *
 * The request is built on the stack. The struct is ~772 bytes (see
 * tmeFuseWriteMultipleReq_t), which fits the stack of a thread. It is not
 * static as in TF-A: OP-TEE is multi-threaded, so a shared buffer would be
 * a data race between two threads building a request.
 */

#include <drivers/qcom/tme/tme_intf.h>
#include <drivers/qcom/tme/tme_intf_defs.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#include "tme_message.h"
#include "tme_tags.h"

TEE_Result tme_fuse_write_multiple(TMEFuse_t *fuse_array,
				   size_t fuse_array_len,
				   uint32_t *const qfprom_api_status)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	tmeFuseWriteMultipleReq_t fuse_write_req;
	tmeFuseWriteMultipleRsp_t rsp = { };
	size_t response_len = sizeof(rsp);
	size_t i = 0;

	if (!fuse_array || !qfprom_api_status)
		return TEE_ERROR_BAD_PARAMETERS;

	if (fuse_array_len == 0U)
		return TEE_ERROR_BAD_PARAMETERS;

	if (fuse_array_len > TME_MAX_FUSE_WRITE_REQ)
		return TEE_ERROR_EXCESS_DATA;

	*qfprom_api_status = TME_QFPROM_STATUS_UNSET;

	/*
	 * The whole fixed-size struct goes on the wire, so clear it first:
	 * without this, the stack garbage in the unused tail would be
	 * presented to TME FW. TME FW only honours the first fuse_array_len
	 * entries, but do not rely on that to keep it harmless.
	 */
	memset(&fuse_write_req, 0, sizeof(fuse_write_req));

	fuse_write_req.fuse_array_len = (uint32_t)fuse_array_len;

	for (i = 0U; i < fuse_array_len; i++) {
		fuse_write_req.fuse_array[i].addr = fuse_array[i].addr;
		fuse_write_req.fuse_array[i].data[0] = fuse_array[i].data[0];
		fuse_write_req.fuse_array[i].data[1] = fuse_array[i].data[1];
	}

	res = tme_transceive_message(TME_MSG_CBOR_TAG_FUSE_WRITE_MULTIPLE,
				     &fuse_write_req, sizeof(fuse_write_req),
				     &rsp, sizeof(rsp), &response_len);
	if (res != TEE_SUCCESS)
		return res;

	if (response_len != sizeof(rsp))
		return TEE_ERROR_GENERIC;

	/*
	 * The caller's qfprom_api_status receives rsp.status (TME's handler
	 * status), not rsp.addr_err. rsp.addr_err carries the qfprom driver's
	 * address/error detail and is dropped here - surface it through a wider
	 * signature if it is ever needed for diagnostics.
	 */
	*qfprom_api_status = rsp.status;

	return (rsp.status == TME_QFPROM_NO_ERR) ? TEE_SUCCESS :
						   TEE_ERROR_GENERIC;
}
