/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 */

#ifndef PLAT_ROCKCHIP_GRF_H
#define PLAT_ROCKCHIP_GRF_H

#if defined(PLATFORM_FLAVOR_rk322x)
#define GRF_CPU_STATUS1		0x524

#define CORE_WFE_MASK(core)	SHIFT_U32(0x02, (core))
#define CORE_WFI_MASK(core)	SHIFT_U32(0x20, (core))
#define CORE_WFE_I_MASK(core)	(CORE_WFI_MASK(core) | CORE_WFE_MASK(core))
#endif

#endif
