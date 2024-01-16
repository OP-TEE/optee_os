/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			32

/* SoC interface registers base address ranges */
#define APB1_BASE			0x40000000
#define APB1_SIZE			0x00200000
#define APB2_BASE			0x40200000
#define APB2_SIZE			0x00040000
#define AHB2_BASE			0x40400000
#define AHB2_SIZE			0x01c00000
#define AHB3_BASE			0x42000000
#define AHB3_SIZE			0x02000000
#define APB3_BASE			0x44000000
#define APB3_SIZE			0x001f0000
#define AHB4_BASE			0x44200000
#define AHB4_SIZE			0x01e00000
#define SAPB_BASE			0x46000000
#define SAPB_SIZE			0x00200000
#define SAHB_BASE			0x46200000
#define SAHB_SIZE			0x01e00000
#define APB4_BASE			0x48000000
#define APB4_SIZE			0x00200000
#define AHB5_BASE			0x48200000
#define AHB5_SIZE			0x01e00000

/* SoC interface registers base address */
#define UART2_BASE			0x400e0000
#define UART3_BASE			0x400f0000
#define UART4_BASE			0x40100000
#define UART5_BASE			0x40110000
#define I2C4_BASE			0x40150000
#define I2C6_BASE			0x40170000
#define UART6_BASE			0x40220000
#define UART9_BASE			0x402c0000
#define UART1_BASE			0x40330000
#define SPI6_BASE			0x40350000
#define UART7_BASE			0x40370000
#define UART8_BASE			0x40380000
#define OSPI1_BASE			0x40430000
#define OSPI2_BASE			0x40440000
#define HASH1_BASE			0x42010000
#define RNG1_BASE			0x42020000
#define CRYP1_BASE			0x42030000
#define SAES_BASE			0x42050000
#define PKA_BASE			0x42060000
#define RIFSC_BASE			0x42080000
#define RISAF5_BASE			0x420e0000
#define RISAB6_BASE			0x42140000
#define BSEC3_BASE			0x44000000
#define IWDG2_BASE			0x44002000
#define IWDG1_BASE			0x44010000
#define RCC_BASE			0x44200000
#define PWR_BASE			0x44210000
#define SYSCFG_BASE			0x44230000
#define GPIOA_BASE			0x44240000
#define GPIOB_BASE			0x44250000
#define GPIOC_BASE			0x44260000
#define GPIOD_BASE			0x44270000
#define GPIOE_BASE			0x44280000
#define GPIOF_BASE			0x44290000
#define GPIOG_BASE			0x442a0000
#define GPIOH_BASE			0x442b0000
#define GPIOI_BASE			0x442c0000
#define GPIOJ_BASE			0x442d0000
#define GPIOK_BASE			0x442e0000
#define RTC_BASE			0x46000000
#define TAMP_BASE			0x46010000
#define GPIOZ_BASE			0x46200000
#define STGEN_BASE			0x48080000
#define FMC_BASE			0x48200000
#define PCIE_BASE			0x48400000
#define A35SSC_BASE			0x48800000
#define GIC_BASE			0x4ac00000
#define DDR_BASE			UL(0x80000000)

#define SYSRAM_BASE			0x0e000000

#define SRAM1_BASE			0x0e040000

/* GIC resources */
#define GIC_SIZE			0x80000
#define GICC_OFFSET			0x20000
#define GICD_OFFSET			0x10000

/* Console configuration */
#define GIC_SPI_UART4			126

#define TARGET_CPU0_GIC_MASK		BIT(0)
#define TARGET_CPU1_GIC_MASK		BIT(1)
#define TARGET_CPUS_GIC_MASK		GENMASK_32(CFG_TEE_CORE_NB_CORE - 1, 0)

/* USART/UART resources */
#define USART1_BASE			UART1_BASE
#define USART2_BASE			UART2_BASE
#define USART3_BASE			UART3_BASE
#define USART6_BASE			UART6_BASE

#endif /*PLATFORM_CONFIG_H*/
