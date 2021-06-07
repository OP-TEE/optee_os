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

#define STACK_ALIGNMENT       64

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform sama5d2"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported"
#endif

#define CONSOLE_UART_BASE     AT91C_BASE_UART1

#define PL310_BASE          (AT91C_BASE_L2CC)
#define SFR_BASE            (AT91C_BASE_SFR)

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
