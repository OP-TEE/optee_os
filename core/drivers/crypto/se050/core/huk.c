// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <kernel/tee_common_otp.h>
#include <se050.h>
#include <string.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	uint8_t se050_huk[SE050_MODULE_UNIQUE_ID_LEN] = { 0 };
	size_t se050_huk_len = sizeof(se050_huk);
	sss_status_t status = kStatus_SSS_Fail;

	status = sss_se05x_session_prop_get_au8(se050_session,
						kSSS_SessionProp_UID,
						se050_huk, &se050_huk_len);
	if (status != kStatus_SSS_Success)
		return -1;

	if (tee_hash_createdigest(TEE_ALG_SHA256, se050_huk, se050_huk_len,
				  buffer, len))
		return -1;

	return 0;
}
