/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			32

/* SoC interface registers base address */
#define GIC_BASE			0xa0021000ul
#define PWR_BASE			0x50001000
#define RCC_BASE			0x50000000
#define TAMP_BASE			0x5c00a000
#define UART1_BASE			0x5c000000
#define UART2_BASE			0x4000e000
#define UART3_BASE			0x4000f000
#define UART4_BASE			0x40010000
#define UART5_BASE			0x40011000
#define UART6_BASE			0x44003000
#define UART7_BASE			0x40018000
#define UART8_BASE			0x40019000

/* Console configuration */
#define STM32MP1_DEBUG_USART_BASE	UART4_BASE
#define GIC_SPI_UART4			84

#define CONSOLE_UART_BASE		STM32MP1_DEBUG_USART_BASE
#define CONSOLE_UART_SIZE		1024

/* GIC resources */
#define GIC_SIZE			0x2000
#define GICC_OFFSET			0x1000
#define GICD_OFFSET			0x0000

#define GIC_NON_SEC_SGI_0		0
#define GIC_SEC_SGI_0			8
#define GIC_SEC_SGI_1			9

#define TARGET_CPU0_GIC_MASK		BIT(0)
#define TARGET_CPU1_GIC_MASK		BIT(1)
#define TARGET_CPUS_GIC_MASK		GENMASK_32(CFG_TEE_CORE_NB_CORE - 1, 0)

/* TAMP resources */
#define TAMP_BKP_REGISTER_OFF		0x100

/* USART/UART resources */
#define USART1_BASE			UART1_BASE
#define USART2_BASE			UART2_BASE
#define USART3_BASE			UART3_BASE
#define USART6_BASE			UART6_BASE

#endif /*PLATFORM_CONFIG_H*/
