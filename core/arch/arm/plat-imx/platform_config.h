/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2018 NXP
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <imx-regs.h>

#define STACK_ALIGNMENT			64

/* For i.MX7D/S platforms */
#if defined(CFG_MX7)
#include <config/config_imx7.h>
/* For i.MX7ULP platforms */
#elif defined(CFG_MX7ULP)
#include <config/config_imx7ulp.h>
/* For i.MX 6UltraLite and 6ULL EVK board */
#elif defined(CFG_MX6UL) || defined(CFG_MX6ULL)
#include <config/config_imx6ul.h>
/* For i.MX6 Quad SABRE Lite and Smart Device board */
#elif defined(CFG_MX6QP) || defined(CFG_MX6Q) || defined(CFG_MX6D) || \
	defined(CFG_MX6DL) || defined(CFG_MX6S)
#include <config/config_imx6q.h>
/* For i.MX 6SL */
#elif defined(CFG_MX6SL)
#include <config/config_imx6sl.h>
/* For i.MX 6SLL */
#elif defined(CFG_MX6SLL)
#include <config/config_imx6sll.h>
#elif defined(CFG_MX6SX)
#include <config/config_imx6sx.h>
#else
#error "Unknown platform flavor"
#endif

#endif /*PLATFORM_CONFIG_H*/
