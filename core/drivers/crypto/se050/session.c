// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <config.h>
#include <initcall.h>
#include <se050.h>

sss_se05x_key_store_t *se050_kstore;
sss_se05x_session_t *se050_session;
struct sss_se05x_ctx se050_ctx;

TEE_Result se050_core_early_init(struct se050_scp_key *keys)
{
	sss_status_t status = kStatus_SSS_Success;

	status = se050_session_open(&se050_ctx, keys);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	if (IS_ENABLED(CFG_CORE_SE05X_INIT_NVM)) {
		status = se050_factory_reset(&se050_ctx.session.s_ctx);
		if (status != kStatus_SSS_Success)
			return TEE_ERROR_GENERIC;
	}

	if (se050_ctx.session.subsystem == kType_SSS_SubSystem_NONE)
		return TEE_ERROR_GENERIC;

	status = se050_key_store_and_object_init(&se050_ctx);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	se050_session = (sss_se05x_session_t *)((void *)&se050_ctx.session);
	se050_kstore = (sss_se05x_key_store_t *)((void *)&se050_ctx.ks);

	return TEE_SUCCESS;
}

static TEE_Result display_info(void)
{
	se050_display_board_info(se050_session);
	/* the session must be closed after accessing board information */
	sss_se05x_session_close(se050_session);

	return se050_core_early_init(NULL);
}

static TEE_Result enable_scp03(void)
{
	if (se050_enable_scp03(se050_session) != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result se050_early_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = se050_core_early_init(NULL);

	if (!ret && IS_ENABLED(CFG_CORE_SE05X_DISPLAY_INFO))
		ret = display_info();

	if (!ret && IS_ENABLED(CFG_CORE_SE05X_SCP03_EARLY))
		return enable_scp03();

	return ret;
}

driver_init(se050_early_init);
