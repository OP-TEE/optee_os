// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto_se.h>
#include <config.h>
#include <se050.h>

TEE_Result crypto_se_enable_scp03(bool rotate_keys)
{
	sss_status_t status = kStatus_SSS_Success;

	status = se050_enable_scp03(se050_session);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	if (rotate_keys) {
		if (IS_ENABLED(CFG_CORE_SE05X_SCP03_PROVISION)) {
			status = se050_rotate_scp03_keys(&se050_ctx);
			if (status != kStatus_SSS_Success)
				return TEE_ERROR_GENERIC;

			return TEE_SUCCESS;
		}
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}
