/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020 Pengutronix
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */
#ifndef __DRIVERS_IMX_SNVS_H
#define __DRIVERS_IMX_SNVS_H

#include <tee_api_types.h>

#define SNVS_HPSR	0x14

#define HPSR_SSM_ST_MASK			GENMASK_32(11, 8)
#define HPSR_SSM_ST_SHIFT			8

#define SNVS_HPSR_SYS_SECURITY_BAD BIT(14)
#define SNVS_HPSR_SYS_SECURITY_CLOSED BIT(13)
#define SNVS_HPSR_SYS_SECURITY_OPEN BIT(12)

enum snvs_ssm_mode {
	SNVS_SSM_MODE_INIT,
	SNVS_SSM_MODE_HARD_FAIL,
	SNVS_SSM_MODE_SOFT_FAIL = 3,
	SNVS_SSM_MODE_INIT_INTERMEDIATE = 8,
	SNVS_SSM_MODE_CHECK,
	SNVS_SSM_MODE_NON_SECURE = 11,
	SNVS_SSM_MODE_TRUSTED = 13,
	SNVS_SSM_MODE_SECURE,
};

enum snvs_security_cfg {
	SNVS_SECURITY_CFG_FAB,
	SNVS_SECURITY_CFG_OPEN,
	SNVS_SECURITY_CFG_CLOSED,
	SNVS_SECURITY_CFG_FIELD_RETURN,
};

enum snvs_ssm_mode snvs_get_ssm_mode(void);

enum snvs_security_cfg snvs_get_security_cfg(void);

#endif /* __DRIVERS_IMX_SNVS_H */
