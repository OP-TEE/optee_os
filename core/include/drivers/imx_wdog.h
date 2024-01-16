/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
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

#ifndef __DRIVERS_IMX_WDOG_H
#define __DRIVERS_IMX_WDOG_H

#include <compiler.h>

/* i.MX6/7D */
#define WDT_WCR		0x00
#define WDT_WCR_WDA	BIT(5)
#define WDT_WCR_SRS	BIT(4)
#define WDT_WCR_WRE	BIT(3)
#define WDT_WCR_WDE	BIT(2)
#define WDT_WCR_WDZST	BIT(0)

#define WDT_WSR		0x02
#define WDT_SEQ1	0x5555
#define WDT_SEQ2	0xAAAA

/* 7ULP */
#define WDOG_CNT	0x4
#define WDOG_TOVAL	0x8

#define REFRESH_SEQ0	0xA602
#define REFRESH_SEQ1	0xB480
#define REFRESH		((REFRESH_SEQ1 << 16) | REFRESH_SEQ0)

#define UNLOCK_SEQ0	0xC520
#define UNLOCK_SEQ1	0xD928
#define UNLOCK		((UNLOCK_SEQ1 << 16) | UNLOCK_SEQ0)

#define WDOG_CS			0x0
#define WDOG_CS_CMD32EN		BIT(13)
#define WDOG_CS_ULK		BIT(11)
#define WDOG_CS_RCS		BIT(10)
#define WDOG_CS_EN		BIT(7)
#define WDOG_CS_UPDATE		BIT(5)

/* Exposed for psci reset */
void __noreturn imx_wdog_restart(bool external_reset);
#endif
