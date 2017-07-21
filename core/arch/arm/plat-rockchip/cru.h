/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PLAT_ROCKCHIP_CRU_H
#define PLAT_ROCKCHIP_CRU_H

#include <platform_config.h>

#if defined(PLATFORM_FLAVOR_rk322x)
#define CRU_SOFTRST_CON(i)		(0x110 + ((i) * 4))
#define CRU_MODE_CON			0x040
#define CRU_GLBRST_CFG_BASE		0x140
#define CRU_FSTRST_VAL_BASE		0x1f0
#define CRU_SNDRST_VAL_BASE		0x1f4
#define CRU_FSTRST_VAL			0xfdb9
#define CRU_SNDRST_VAL			0xeca8
#define PLLS_SLOW_MODE			0x11030000

#define CORE_SOFT_RESET(core)		SHIFT_U32(0x100010, (core))
#define CORE_SOFT_RELEASE(core)		SHIFT_U32(0x100000, (core))
#define CORE_HELD_IN_RESET(core)	SHIFT_U32(0x000010, (core))
#define NONBOOT_CORES_SOFT_RESET	0x00e000e0
#endif

#endif
