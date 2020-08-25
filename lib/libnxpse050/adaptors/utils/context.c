// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <initcall.h>
#include <kernel/panic.h>
#include <se050.h>

sss_se05x_key_store_t *se050_kstore;
sss_se05x_session_t *se050_session;
struct sss_se05x_ctx se050_ctx;

TEE_Result se050_core_service_init(struct se050_scp_key *keys)
{
	sss_status_t status = kStatus_SSS_Success;

	status = se050_session_open(&se050_ctx, keys);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

#if defined(CFG_CORE_SE05X_INIT_NVM)
	IMSG("========================");
	IMSG(" WARNING: FACTORY RESET");
	IMSG("========================");
	status = se050_factory_reset(&se050_ctx.session.s_ctx);
	if (kStatus_SSS_Success != status)
		return TEE_ERROR_GENERIC;
#endif
	if (se050_ctx.session.subsystem == kType_SSS_SubSystem_NONE)
		return TEE_ERROR_GENERIC;

	status = se050_key_store_and_object_init(&se050_ctx);
	if (status != kStatus_SSS_Success)
		return TEE_ERROR_GENERIC;

	se050_session = (sss_se05x_session_t *)((void *)&se050_ctx.session);
	se050_kstore = (sss_se05x_key_store_t *)((void *)&se050_ctx.ks);

	return TEE_SUCCESS;
}

static TEE_Result se050_service_init(void)
{
	if (se050_core_service_init(NULL) != TEE_SUCCESS)
		panic();

#if defined(CFG_CORE_SE05X_DISPLAY_INFO)
	se050_display_board_info(se050_session);

	/* a reinit is required if display info is executed */
	sss_se05x_session_close(se050_session);
	if (se050_core_service_init(NULL) != TEE_SUCCESS)
		panic();
#endif
	IMSG("se050 ready [scp03 off]");
#if defined (CFG_CORE_SE05X_SCP03_EARLY)
	/*
	 * Use keys in config or the default OFID to start the scp03 service
	 * early. If the keys were already rotated and are kept in scp.db then
	 * this will panic.
	 */
	if (se050_enable_scp03(se050_session) != kStatus_SSS_Success)
		panic();
/*
 * Do not provision the keys at this point unless there is guaranteed access to
 * trusted storage.
 *
 * This can be done once RPMB is accessible and we can test it
 *
 * #if defined(CFG_CORE_SE05X_SCP03_PROVISION)
 *	if (se050_rotate_scp03_keys(&se050_ctx) != kStatus_SSS_Success)
 *		panic();
 * #endif
 */
#endif
	return TEE_SUCCESS;
}

service_init(se050_service_init);
