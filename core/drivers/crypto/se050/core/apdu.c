// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2021 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <apdu.h>
#include <config.h>
#include <crypto/crypto_se.h>
#include <se050.h>

TEE_Result crypto_se_do_apdu(enum crypto_apdu_type type,
			     uint8_t *hdr, size_t hdr_len,
			     uint8_t *src_data, size_t src_len,
			     uint8_t *dst_data, size_t *dst_len)
{
	sss_status_t status = kStatus_SSS_Fail;

	status = sss_se05x_do_apdu(&se050_session->s_ctx, type,
				   hdr, hdr_len, src_data, src_len,
				   dst_data, dst_len);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
