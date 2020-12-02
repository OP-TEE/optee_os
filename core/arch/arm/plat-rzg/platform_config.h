/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, GlobalLogic
 * Copyright (c) 2020, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GIC_BASE		0xF1000000
#define GICC_BASE		0xF1020000
#define GICD_BASE		0xF1010000

#define CONSOLE_UART_BASE	0xE6E88000

#if defined(PLATFORM_FLAVOR_ek874)
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000

#elif defined(PLATFORM_FLAVOR_hihope_rzg2h)

#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x500000000U
#define NSEC_DDR_1_SIZE		0x80000000

#elif defined(PLATFORM_FLAVOR_hihope_rzg2m)

#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x600000000U
#define NSEC_DDR_1_SIZE		0x80000000

#elif defined(PLATFORM_FLAVOR_hihope_rzg2n)

#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x480000000U
#define NSEC_DDR_1_SIZE		0x80000000

#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x100000

#endif /*PLATFORM_CONFIG_H*/
