/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 * Copyright 2021 NXP
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

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define STACK_ALIGNMENT			64

/* console uart define */
#define CONSOLE_UART_BASE		UART0_BASE

/* Platform specific defines */
#if defined(PLATFORM_FLAVOR_ls1012ardb)
/*  DUART 1 */
#define UART0_BASE			0x021C0500
#define GIC_BASE			0x01400000
#define GICC_OFFSET			0x2000
#define GICD_OFFSET			0x1000
#define CAAM_BASE			0x01700000
#define CAAM_SIZE			0x100000
#endif

#if defined(PLATFORM_FLAVOR_ls1043ardb)
#define UART0_BASE		0x021C0500
#define GIC_BASE		0x01400000
#define GICC_OFFSET_REV1	0x2000
#define GICD_OFFSET_REV1	0x1000
#define GICC_OFFSET_REV1_1	0x20000
#define GICD_OFFSET_REV1_1	0x10000
#define CAAM_BASE		0x01700000
#define CAAM_SIZE		0x100000
#define DCFG_BASE		0x01EE0000
#define DCFG_SVR_OFFSET		0xA4
#endif

#if defined(PLATFORM_FLAVOR_ls1046ardb)
/*  DUART 1 */
#define UART0_BASE			0x021C0500
#define GIC_BASE			0x01400000
#define GICC_OFFSET			0x20000
#define GICD_OFFSET			0x10000
#define CAAM_BASE			0x01700000
#define CAAM_SIZE			0x100000
#endif

#if defined(PLATFORM_FLAVOR_ls1088ardb)
/*  DUART 1 */
#define UART0_BASE			0x021C0500
#define GIC_BASE			0x06000000
#define GICC_OFFSET			0x0
#define GICD_OFFSET			0x0
#define CAAM_BASE			0x08000000
#define CAAM_SIZE			0x100000
#endif

#if defined(PLATFORM_FLAVOR_ls2088ardb)
/*  DUART 1 */
#define UART0_BASE			0x021C0600
#define GIC_BASE			0x06000000
#define GICC_OFFSET			0x0
#define GICD_OFFSET			0x0
#define CAAM_BASE			0x08000000
#define CAAM_SIZE			0x100000
#endif

#if defined(PLATFORM_FLAVOR_ls1028ardb)
/*  DUART 1 */
#define UART0_BASE			0x021C0500
#define GIC_BASE			0x06000000
#define GICC_OFFSET			0x0
#define GICD_OFFSET			0x0
#define CAAM_BASE			0x08000000
#define CAAM_SIZE			0x100000
#endif

#if defined(PLATFORM_FLAVOR_lx2160ardb)
/*  DUART 1 */
#define UART0_BASE			0x021C0000
#define GIC_BASE			0x06000000
#define GICC_OFFSET			0x0
#define GICD_OFFSET			0x0
#define CAAM_BASE			0x08000000
#define CAAM_SIZE			0x100000
#endif

#if defined(PLATFORM_FLAVOR_lx2160aqds)
/*  DUART 1 */
#define UART0_BASE                      0x021C0000
#define GIC_BASE                        0x06000000
#define GICC_OFFSET                     0x0
#define GICD_OFFSET                     0x0
#define CAAM_BASE                       0x08000000
#define CAAM_SIZE                       0x100000
#endif

#endif /*PLATFORM_CONFIG_H*/
