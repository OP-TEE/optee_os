/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
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

#ifndef CONFIG_IMX6QDLSOLO_H
#define CONFIG_IMX6QDLSOLO_H

/*
 * PL310 TAG RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:3 - 4 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#ifndef PL310_TAG_RAM_CTRL_INIT
#define PL310_TAG_RAM_CTRL_INIT		0x00000132
#endif

/*
 * PL310 DATA RAM Control Register
 *
 * bit[10:8]:1 - 2 cycle of write accesses latency
 * bit[6:4]:3 - 4 cycle of read accesses latency
 * bit[2:0]:2 - 3 cycle of setup latency
 */
#ifndef PL310_DATA_RAM_CTRL_INIT
#define PL310_DATA_RAM_CTRL_INIT	0x00000132
#endif

/*
 * PL310 Auxiliary Control Register
 */
#ifndef PL310_AUX_CTRL_INIT
#if defined(CFG_MX6QP) || defined(CFG_MX6Q) || defined(CFG_MX6D)
/*
 * Early BRESP enabled (bit30=1)
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockown cache lines (bit26=1)
 * Pseudo-random replacement policy (bit25=1)
 * Force write allocated (default) (bit24:23=00)
 * Shared attribute internally ignored (bit22=1, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * 64kb way size (bit19:17=3b011)
 * 16-way associativity (bit16=1)
 * Store buffer device limitation disabled (bit11=0)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) enabled (bit0=1)
 */
#define PL310_AUX_CTRL_INIT		0x7E470001
#else
/*
 * Early BRESP enabled (bit30=0)
 * I/Dcache prefetch enabled (bit29:28=2b11)
 * NS can access interrupts (bit27=1)
 * NS can lockown cache lines (bit26=1)
 * Pseudo-random replacement policy (bit25=0)
 * Force write allocated (default) (bit24:23=00)
 * Shared attribute internally ignored (bit22=1, bit13=0)
 * Parity disabled (bit21=0)
 * Event monitor disabled (bit20=0)
 * 32kb way size (bit19:17=3b010)
 * 8-way associativity (bit16=0)
 * Store buffer device limitation enabled (bit11=1)
 * Cacheable accesses have high prio (bit10=0)
 * Full Line Zero (FLZ) disabled (bit0=0)
 */
#define PL310_AUX_CTRL_INIT		0x3C440800
#endif
#endif

/*
 * PL310 Prefetch Control Register
 *
 * Double linefill enabled (bit30=1)
 * I/D prefetch enabled (bit29:28=2b11)
 * Prefetch drop disabled (bit24=0)
 * Incr double linefill disable (bit23=0)
 * Prefetch offset = 0xF (bit4:0)
 */
#define PL310_PREFETCH_CTRL_INIT	0x7000000F

/*
 * PL310 Power Register
 *
 * Dynamic clock gating enabled
 * Standby mode enabled
 */
#define PL310_POWER_CTRL_INIT		0x00000003
#endif
