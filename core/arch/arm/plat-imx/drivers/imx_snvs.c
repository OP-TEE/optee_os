// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 Pengutronix, Rouven Czerwinski <entwicklung@pengutronix.de>
 */
#include <drivers/imx_snvs.h>
#include <tee/tee_fs.h>

bool plat_rpmb_ready(void)
{
	enum snvs_ssm_mode mode = SNVS_SSM_MODE_INIT;
	enum snvs_security_cfg security = SNVS_SECURITY_CFG_OPEN;

	mode = snvs_get_ssm_mode();
	security = snvs_get_security_cfg();
	return (mode == SNVS_SSM_MODE_TRUSTED ||
		mode == SNVS_SSM_MODE_SECURE) &&
		(security == SNVS_SECURITY_CFG_CLOSED);
}
