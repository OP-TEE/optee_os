// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 Pengutronix, Rouven Czerwinski <entwicklung@pengutronix.de>
 */
#include <drivers/imx_snvs.h>
#include <imx.h>
#include <tee/tee_fs.h>

bool plat_rpmb_key_is_ready(void)
{
	enum snvs_ssm_mode mode = SNVS_SSM_MODE_INIT;
	enum snvs_security_cfg security = SNVS_SECURITY_CFG_OPEN;
	bool ssm_secure = false;

	mode = snvs_get_ssm_mode();
	security = snvs_get_security_cfg();
	ssm_secure = (mode == SNVS_SSM_MODE_TRUSTED ||
		      mode == SNVS_SSM_MODE_SECURE);

	/*
	 * On i.MX6SDL and i.MX6DQ, the security cfg always returns
	 * SNVS_SECURITY_CFG_FAB (000), therefore we ignore the security
	 * configuration for this SoC.
	 */
	if (soc_is_imx6sdl() || soc_is_imx6dq())
		return ssm_secure;

	return ssm_secure && (security == SNVS_SECURITY_CFG_CLOSED);
}
