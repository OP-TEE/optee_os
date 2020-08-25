// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <crypto/crypto.h>
#include <se050.h>

TEE_Result crypto_enable_scp03(unsigned int rotate_keys)
{
	sss_status_t status;

	status = se050_enable_scp03(se050_session);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

#if defined(CFG_CORE_SE05X_SCP03_PROVISION)
	if (rotate_keys) {
		status = se050_rotate_scp03_keys(&se050_ctx);
		if (status != kStatus_SSS_Success)
			return TEE_ERROR_GENERIC;
	}
#else
	if (rotate_keys)
		EMSG("scp03 key rotation not enabled in config");
#endif
	return TEE_SUCCESS;
}
