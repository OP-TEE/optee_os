/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			64

#if defined(PLATFORM_FLAVOR_kodiak) || defined(PLATFORM_FLAVOR_lemans)
/* GIC related constants */
#define GICD_BASE			UL(0x17a00000)
#define GICR_BASE			UL(0x17a60000)

#define RAMBLUR_PIMEM_REG_BASE		UL(0x610000)
#define SEC_PRNG_REG_BASE		UL(0x010D1000)
#endif

#if defined(PLATFORM_FLAVOR_kodiak)
#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x80000000)
#define DRAM1_BASE			ULL(0x100000000)
#define DRAM1_SIZE			ULL(0x100000000)

/* DDR reserved*/
#define RAMBLUR_PIMEM_VAULT_TA_BASE	ULL(0xc1800000)
#define RAMBLUR_PIMEM_VAULT_TA_SIZE	ULL(0x01c00000)

#define GENI_UART_REG_BASE		UL(0x994000)
#endif

#if defined(PLATFORM_FLAVOR_lemans)
#define DRAM0_BASE			UL(0x80000000)
#define DRAM0_SIZE			UL(0x380000000)
#define DRAM1_BASE			ULL(0x800000000)
#define DRAM1_SIZE			ULL(0x800000000)

/* DDR reserved*/
#define RAMBLUR_PIMEM_VAULT_TA_BASE	ULL(0xd1900000)
#define RAMBLUR_PIMEM_VAULT_TA_SIZE	ULL(0x01c00000)

#define GENI_UART_REG_BASE		UL(0xa8c000)
#endif

#endif /*PLATFORM_CONFIG_H*/
