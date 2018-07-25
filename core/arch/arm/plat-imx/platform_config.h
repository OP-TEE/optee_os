/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
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

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <imx-regs.h>

#ifndef CFG_DDR_SIZE
#error "CFG_DDR_SIZE not defined"
#endif

#define STACK_ALIGNMENT			64
#define CONSOLE_UART_BASE		(CFG_UART_BASE)

#if defined(CFG_MX6SX)
#include <config/imx6sx.h>

/* For i.MX 6UltraLite and 6ULL EVK board */
#elif defined(CFG_MX6UL) || defined(CFG_MX6ULL)

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform mx6ulevk"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported for now"
#endif

/* For i.MX6 Quad SABRE Lite and Smart Device board */

#elif defined(CFG_MX6Q) || defined(CFG_MX6D) || defined(CFG_MX6DL) || \
	defined(CFG_MX6S)
/*
 * PL310 TAG RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:1 - 2 cycle of read accesses latency
 * bit[2:0]:1 - 2 cycle of setup latency
 */
#ifndef PL310_TAG_RAM_CTRL_INIT
#define PL310_TAG_RAM_CTRL_INIT		0x00000111
#endif

/*
 * PL310 DATA RAM Control Register
 *
 * bit[10:8]:2 - 3 cycle of write accesses latency
 * bit[6:4]:2 - 3 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#ifndef PL310_DATA_RAM_CTRL_INIT
#define PL310_DATA_RAM_CTRL_INIT	0x00000222
#endif

/*
 * PL310 Auxiliary Control Register
 *
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockown cache lines (bit26=1)
 * Pseudo-random replacement policy (bit25=0)
 * Force write allocated (default)
 * Shared attribute internally ignored (bit22=1, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * Platform fmavor specific way config (dual / quad):
 * - 64kb way size (bit19:17=3b011)
 * - 16-way associciativity (bit16=1)
 * Platform fmavor specific way config (dual lite / solo):
 * - 32kb way size (bit19:17=3b010)
 * - no 16-way associciativity (bit16=0)
 * Store buffer device limitation enabled (bit11=1)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) disabled (bit0=0)
 */
#ifndef PL310_AUX_CTRL_INIT
#if defined(CFG_MX6Q) || defined(CFG_MX6D)
#define PL310_AUX_CTRL_INIT		0x3C470800
#else
#define PL310_AUX_CTRL_INIT		0x3C440800
#endif
#endif

/*
 * PL310 Prefetch Control Register
 *
 * Double linefill disabled (bit30=0)
 * I/D prefetch enabled (bit29:28=2b11)
 * Prefetch drop enabled (bit24=1)
 * Incr double linefill disable (bit23=0)
 * Prefetch offset = 7 (bit4:0)
 */
#define PL310_PREFETCH_CTRL_INIT	0x31000007

/*
 * PL310 Power Register
 *
 * Dynamic clock gating enabled
 * Standby mode enabled
 */
#define PL310_POWER_CTRL_INIT		0x00000003

/*
 * SCU Invalidate Register
 *
 * Invalidate all registers
 */
#define	SCU_INV_CTRL_INIT		0xFFFFFFFF

/*
 * SCU Access Register
 * - both secure CPU access SCU
 */
#define SCU_SAC_CTRL_INIT		0x0000000F

/*
 * SCU NonSecure Access Register
 * - both nonsec cpu access SCU, private and global timer
 */
#define SCU_NSAC_CTRL_INIT		0x00000FFF

#endif

#endif /*PLATFORM_CONFIG_H*/
