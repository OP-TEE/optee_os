/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, GlobalLogic
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

#define RCAR_CACHE_LINE_SZ		64

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		RCAR_CACHE_LINE_SZ

#if defined(CFG_RCAR_GEN3)

#define GIC_BASE		0xF1000000
#define GICC_BASE		0xF1020000
#define GICD_BASE		0xF1010000

#define CONSOLE_UART_BASE	0xE6E88000

#define PRR_BASE		0xFFF00000

#elif defined(CFG_RCAR_GEN4)

#define GICC_BASE		0xF1060000
#define GICD_BASE		0xF1000000

#if CFG_RCAR_UART == 103	/* SCIF3 */
#define CONSOLE_UART_BASE	0xE6C50000
#elif CFG_RCAR_UART == 200	/* HSCIF0 */
#define CONSOLE_UART_BASE	0xE6540000
#endif

#endif	/* CFG_RCAR_GENx */

#if defined(PLATFORM_FLAVOR_salvator_h3)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x38200000
#define NSEC_DDR_1_BASE		0x500000000U
#define NSEC_DDR_1_SIZE		0x40000000
#define NSEC_DDR_2_BASE		0x600000000U
#define NSEC_DDR_2_SIZE		0x40000000
#define NSEC_DDR_3_BASE		0x700000000U
#define NSEC_DDR_3_SIZE		0x40000000

#elif defined(PLATFORM_FLAVOR_salvator_h3_4x2g)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x500000000U
#define NSEC_DDR_1_SIZE		0x80000000
#define NSEC_DDR_2_BASE		0x600000000U
#define NSEC_DDR_2_SIZE		0x80000000
#define NSEC_DDR_3_BASE		0x700000000U
#define NSEC_DDR_3_SIZE		0x80000000

#elif defined(PLATFORM_FLAVOR_salvator_m3)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x600000000U
#define NSEC_DDR_1_SIZE		0x80000000

#elif defined(PLATFORM_FLAVOR_salvator_m3_2x4g)
#define NSEC_DDR_0_BASE		0x47E00000
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x480000000U
#define NSEC_DDR_1_SIZE		0x80000000
#define NSEC_DDR_2_BASE		0x600000000U
#define NSEC_DDR_2_SIZE		0x100000000U

#elif defined(PLATFORM_FLAVOR_spider_s4)
#define NSEC_DDR_0_BASE		0x48000000
#define NSEC_DDR_0_SIZE		0x78000000
#define NSEC_DDR_1_BASE		0x480000000U
#define NSEC_DDR_1_SIZE		0x80000000U

#else

/* Generic DT-based platform */

#endif

/* Full GlobalPlatform test suite requires TEE_SHMEM_SIZE to be at least 2MB */
#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x100000

#endif /*PLATFORM_CONFIG_H*/
