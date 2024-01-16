/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2019, 2023 NXP
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
#ifndef PLAT_IMX_IMX_REGS_H
#define PLAT_IMX_IMX_REGS_H

#ifdef CFG_MX6
#include <registers/imx6.h>
#elif defined(CFG_MX7)
#include <registers/imx7.h>
#elif defined(CFG_MX7ULP)
#include <registers/imx7ulp.h>
#elif defined(CFG_MX8MQ) || defined(CFG_MX8MM) || defined(CFG_MX8MN) || \
	defined(CFG_MX8MP)
#include <registers/imx8m.h>
#elif defined(CFG_MX8QX) || defined(CFG_MX8QM) || defined(CFG_MX8DXL)
#include <registers/imx8q.h>
#elif defined(CFG_MX8ULP)
#include <registers/imx8ulp.h>
#elif defined(CFG_MX93)
#include <registers/imx93.h>
#else
#error "CFG_MX* not defined"
#endif
#endif
