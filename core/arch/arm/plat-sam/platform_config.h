/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017 Timesys Corporation.
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
#if defined(PLATFORM_FLAVOR_sama7g54_ek)
#include <sama7g5.h>
#else
#include <sama5d2.h>
#endif

#define STACK_ALIGNMENT       64

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform sama5d2"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported"
#endif

#if defined(PLATFORM_FLAVOR_sama7g54_ek)
#define CONSOLE_UART_BASE   (FLEXCOM3_BASE_ADDRESS + 0x200)
#define SFR_BASE            SFR_BASE_ADDRESS
#define AT91C_BASE_TC0      TC0_BASE_ADDRESS
#define AT91C_ID_TC0        ID_TC0_CHANNEL0
#define AT91C_ID_TC1        ID_TC1_CHANNEL0
#define AT91C_ID_SYS        ID_RSTC
#define AT91C_ID_PIOA       ID_PIOA
#define AT91C_ID_PIOB       ID_PIOB
#define AT91C_ID_PIOC       ID_PIOC
#define AT91C_ID_PIOD       ID_PIOD
#define AT91C_ID_WDT        ID_DWDT_SW
#define AT91C_ID_TRNG       ID_TRNG
#define AT91C_ID_SECUMOD    ID_SECUMOD
#define AT91C_ID_SFR        ID_SFR
#define AT91C_ID_SFRBU      ID_SFRBU
#else
#if defined(PLATFORM_FLAVOR_sama5d27_wlsom1_ek)
#define CONSOLE_UART_BASE     AT91C_BASE_UART0
#else
#define CONSOLE_UART_BASE     AT91C_BASE_UART1
#endif

#define PL310_BASE          (AT91C_BASE_L2CC)
#define SFR_BASE            (AT91C_BASE_SFR)
#endif

/*
 * PL310 Auxiliary Control Register
 *
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockdown cache lines (bit26=1)
 * Round robin replacement policy (bit25=1)
 * Force write allocated (default)
 * Treats shared accesses (bit22=0, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * Platform flavor specific way config:
 * - 16kb way size (bit19:17=3b001)
 * Store buffer device limitation disabled (bit11=0)
 * Cacheable accesses have high prio (bit10=0)
 */
#define PL310_AUX_CTRL_INIT      0x3E020000

/*
 * PL310 Prefetch Control Register
 *
 * Double linefill enabled (bit30=1)
 * I/D prefetch enabled (bit29:28=2b11)
 * Prefetch drop enabled (bit24=1)
 * Incr double linefill enable (bit23=1)
 * Prefetch offset = 1 (bit4:0)
 */
#define PL310_PREFETCH_CTRL_INIT 0x71800001

/*
 * PL310 Power Register
 *
 * Dynamic clock gating enabled
 * Standby mode enabled
 */
#define PL310_POWER_CTRL_INIT    0x00000003

#endif /*PLATFORM_CONFIG_H*/
