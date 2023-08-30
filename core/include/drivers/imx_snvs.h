/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020 Pengutronix
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 * Copyright 2022-2023 NXP
 */
#ifndef __DRIVERS_IMX_SNVS_H
#define __DRIVERS_IMX_SNVS_H

#include <tee_api_types.h>

/* Set the OTPMK Key as Master key */
#ifdef CFG_IMX_SNVS
TEE_Result imx_snvs_set_master_otpmk(void);
bool snvs_is_device_closed(void);
void imx_snvs_shutdown(void);
#else
static inline bool snvs_is_device_closed(void)
{
	return false;
}

static inline TEE_Result imx_snvs_set_master_otpmk(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline void imx_snvs_shutdown(void) {}
#endif

#endif /* __DRIVERS_IMX_SNVS_H */
