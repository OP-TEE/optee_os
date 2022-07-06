/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			32

/* SoC interface registers base address ranges */
#define APB1_BASE			0x40000000
#define APB1_SIZE			0x0001d000
#define APB2_BASE			0x44000000
#define APB2_SIZE			0x00014000
#define APB3_BASE			0x50020000
#define APB3_SIZE			0x0000b000
#define APB4_BASE			0x5a000000
#define APB4_SIZE			0x00008000
#define APB5_BASE			0x5c000000
#define APB5_SIZE			0x0000b000
#ifdef CFG_STM32MP13
#define APB6_BASE			0x4c000000
#define APB6_SIZE			0x0000d000
#endif

#define AHB4_BASE			0x50000000
#define AHB4_SIZE			0x00020000
#ifdef CFG_STM32MP13
#define AHB5_BASE			0x54000000
#define AHB5_SIZE			0x00008000
#endif
#ifdef CFG_STM32MP15
#define AHB5_BASE			0x54000000
#define AHB5_SIZE			0x00005000
#endif

/* SoC interface registers base address */
#define BSEC_BASE			0x5c005000
#define ETZPC_BASE			0x5c007000
#define CRYP1_BASE			0x54001000
#define DDR_BASE			0xc0000000ul
#define GIC_BASE			0xa0021000ul
#define GPIOA_BASE			0x50002000
#define GPIOB_BASE			0x50003000
#define GPIOC_BASE			0x50004000
#define GPIOD_BASE			0x50005000
#define GPIOE_BASE			0x50006000
#define GPIOF_BASE			0x50007000
#define GPIOG_BASE			0x50008000
#define GPIOH_BASE			0x50009000
#define GPIOI_BASE			0x5000a000
#define GPIOJ_BASE			0x5000b000
#define GPIOK_BASE			0x5000c000
#define GPIOZ_BASE			0x54004000
#define HASH1_BASE			0x54002000
#define I2C4_BASE			0x5c002000
#define I2C6_BASE			0x5c009000
#define IWDG1_BASE			0x5c003000
#define IWDG2_BASE			0x5a002000
#define PWR_BASE			0x50001000
#define RCC_BASE			0x50000000
#ifdef CFG_STM32MP13
#define RNG1_BASE			0x54004000
#endif
#ifdef CFG_STM32MP15
#define RNG1_BASE			0x54003000
#endif
#define RTC_BASE			0x5c004000
#define SPI6_BASE			0x5c001000
#define SYSCFG_BASE			0x50020000
#ifdef CFG_STM32MP13
#define SYSRAM_BASE			0x2ffe0000
#endif
#ifdef CFG_STM32MP15
#define SYSRAM_BASE			0x2ffc0000
#endif
#define TAMP_BASE			0x5c00a000
#define TZC_BASE			0x5c006000
#ifdef CFG_STM32MP13
#define UART1_BASE			0x4c000000
#define UART2_BASE			0x4c001000
#endif
#ifdef CFG_STM32MP15
#define UART1_BASE			0x5c000000
#define UART2_BASE			0x4000e000
#endif
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

/* BSEC OTP resources */
#define STM32MP1_OTP_MAX_ID		0x5FU
#define STM32MP1_UPPER_OTP_START	0x20U

#define OTP_MAX_SIZE			(STM32MP1_OTP_MAX_ID + 1U)

#define DATA0_OTP			0
#define PART_NUMBER_OTP			1
#define MONOTONIC_OTP			4
#define NAND_OTP			9
#define UID0_OTP			13
#define UID1_OTP			14
#define UID2_OTP			15
#define HW2_OTP				18

/* Bit map for BSEC word HW2_OTP */
#define HW2_OTP_IWDG_HW_ENABLE_SHIFT	U(3)
#define HW2_OTP_IWDG_FZ_STOP_SHIFT	U(5)
#define HW2_OTP_IWDG_FZ_STANDBY_SHIFT	U(7)

#define DATA0_OTP_SECURED_POS		6

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

/*
 * GPIO banks: 11 non secure banks (A to K) and 1 secure bank (Z)
 * Bank register's base address is computed from the bank ID listed here.
 */
#define GPIOS_NSEC_COUNT		11
#define GPIOS_NSEC_BASE			GPIOA_BASE
#define GPIOS_NSEC_SIZE			(GPIOS_NSEC_COUNT * SMALL_PAGE_SIZE)

#define STM32MP1_GPIOZ_MAX_COUNT	1
#define STM32MP1_GPIOZ_PIN_MAX_COUNT	8

#define GPIO_BANK_OFFSET		0x1000U

/* Bank IDs used in GPIO driver API */
#define GPIO_BANK_A			0U
#define GPIO_BANK_B			1U
#define GPIO_BANK_C			2U
#define GPIO_BANK_D			3U
#define GPIO_BANK_E			4U
#define GPIO_BANK_F			5U
#define GPIO_BANK_G			6U
#define GPIO_BANK_H			7U
#define GPIO_BANK_I			8U
#define GPIO_BANK_J			9U
#define GPIO_BANK_K			10U
#define GPIO_BANK_Z			25U

/* TAMP resources */
#define TAMP_BKP_REGISTER_OFF		0x100
#define TAMP_BKP_REGISTER_COUNT		U(32)

#define TAMP_BKP_REGISTER_ZONE1_COUNT	U(10)
#define TAMP_BKP_REGISTER_ZONE2_COUNT	U(5)
#define TAMP_BKP_REGISTER_ZONE3_COUNT	U(17)

#if (TAMP_BKP_REGISTER_ZONE1_COUNT + TAMP_BKP_REGISTER_ZONE2_COUNT + \
	TAMP_BKP_REGISTER_ZONE3_COUNT != TAMP_BKP_REGISTER_COUNT)
#error Inconsistent TAMP backup register zone definition
#endif

/* TZC resources */
#define STM32MP1_IRQ_TZC		36

#define STM32MP1_TZC_A7_ID		0
#define STM32MP1_TZC_M4_ID		1
#define STM32MP1_TZC_LCD_ID		3
#define STM32MP1_TZC_GPU_ID		4
#define STM32MP1_TZC_MDMA_ID		5
#define STM32MP1_TZC_DMA_ID		6
#define STM32MP1_TZC_USB_HOST_ID	7
#define STM32MP1_TZC_USB_OTG_ID		8
#define STM32MP1_TZC_SDMMC_ID		9
#define STM32MP1_TZC_ETH_ID		10
#define STM32MP1_TZC_DAP_ID		15

/* USART/UART resources */
#define USART1_BASE			UART1_BASE
#define USART2_BASE			UART2_BASE
#define USART3_BASE			UART3_BASE
#define USART6_BASE			UART6_BASE

/* SYSRAM layout */
#define SYSRAM_SIZE			0x40000
#define SYSRAM_NS_SIZE			(SYSRAM_SIZE - SYSRAM_SEC_SIZE)

/* Non-secure SYSRAM must be above (higher addresses) secure SYSRAM */
#if (CFG_STM32MP1_SCMI_SHM_BASE >= SYSRAM_BASE) && \
	((CFG_STM32MP1_SCMI_SHM_BASE + CFG_STM32MP1_SCMI_SHM_SIZE) <= \
	 (SYSRAM_BASE + SYSRAM_SIZE))
#define SYSRAM_SEC_SIZE		(CFG_STM32MP1_SCMI_SHM_BASE - SYSRAM_BASE)
#else
#define SYSRAM_SEC_SIZE		SYSRAM_SIZE
#endif

#endif /*PLATFORM_CONFIG_H*/
