/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2016-2018 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

#define UART0_BASE      0x02800000

#define CONSOLE_UART_BASE       (UART0_BASE + CFG_CONSOLE_UART * 0x10000)
#define CONSOLE_BAUDRATE        115200
#define CONSOLE_UART_CLK_IN_HZ  48000000

#define DRAM0_BASE      0x80000000
#define DRAM0_SIZE      0x80000000

#define DRAM1_BASE      0x880000000
#define DRAM1_SIZE      0x780000000

#define SCU_BASE        0x01800000
#if defined(PLATFORM_FLAVOR_j721e) || defined(PLATFORM_FLAVOR_j784s4)
#define GICC_OFFSET     0x100000
#define GICC_SIZE       0x100000
#define GICD_OFFSET     0x0
#define GICD_SIZE       0x10000
#else
#define GICC_OFFSET     0x80000
#define GICC_SIZE       0x90000
#define GICD_OFFSET     0x0
#define GICD_SIZE       0x10000
#endif
#if defined(PLATFORM_FLAVOR_am62lx)
#define TI_MAILBOX_SYSC			0x10UL
#define TI_MAILBOX_MSG			0x40UL
#define TI_MAILBOX_FIFO_STATUS		0x80UL
#define TI_MAILBOX_MSG_STATUS		0xc0UL
#define TI_MAILBOX_TX_BASE		0x44240000UL
#define TI_MAILBOX_RX_BASE		0x44250000UL
#define MAILBOX_TX_START_REGION		0x70814000UL
#define MAILBOX_RX_START_REGION		0x70815000UL
#define MAILBOX_MAX_MESSAGE_SIZE	56U
#define OPTEE_HOST_ID			10
#elif defined(PLATFORM_FLAVOR_am65x) || defined(PLATFORM_FLAVOR_j721e) || \
	defined(PLATFORM_FLAVOR_j784s4)
#define SEC_PROXY_DATA_BASE             0x32c00000
#define SEC_PROXY_DATA_SIZE             0x100000
#define SEC_PROXY_SCFG_BASE             0x32800000
#define SEC_PROXY_SCFG_SIZE             0x100000
#define SEC_PROXY_RT_BASE               0x32400000
#define SEC_PROXY_RT_SIZE               0x100000
#define SEC_PROXY_RESPONSE_THREAD       6
#define SEC_PROXY_REQUEST_THREAD        7
#define OPTEE_HOST_ID                   11
#else
#define SEC_PROXY_DATA_BASE             0x4d000000
#define SEC_PROXY_DATA_SIZE             0x80000
#define SEC_PROXY_SCFG_BASE             0x4a400000
#define SEC_PROXY_SCFG_SIZE             0x80000
#define SEC_PROXY_RT_BASE               0x4a600000
#define SEC_PROXY_RT_SIZE               0x80000
#define SEC_PROXY_RESPONSE_THREAD       10
#define SEC_PROXY_REQUEST_THREAD        11
#define OPTEE_HOST_ID                   11
#endif
#define SEC_PROXY_TIMEOUT_US            1000000
#define GICC_BASE       (SCU_BASE + GICC_OFFSET)
#define GICD_BASE       (SCU_BASE + GICD_OFFSET)

/* SA2UL */
#if defined(PLATFORM_FLAVOR_am65x)
#define SA2UL_BASE		0x04e00000
#define SA2UL_TI_SCI_DEV_ID	136
#define SA2UL_TI_SCI_FW_ID	2112
#define SA2UL_TI_SCI_FW_RGN_ID	0
#elif defined(PLATFORM_FLAVOR_j721e)
#define SA2UL_BASE		0x40900000
#define SA2UL_TI_SCI_DEV_ID	265
#define SA2UL_TI_SCI_FW_ID	1196
#define SA2UL_TI_SCI_FW_RGN_ID	0
#elif defined(PLATFORM_FLAVOR_j784s4)
#define SA2UL_BASE		0x40900000
#define SA2UL_TI_SCI_DEV_ID	-1
#define SA2UL_TI_SCI_FW_ID	1196
#define SA2UL_TI_SCI_FW_RGN_ID	0
#elif defined(PLATFORM_FLAVOR_am64x)
#define SA2UL_BASE		0x40900000
#define SA2UL_TI_SCI_DEV_ID	133
#define SA2UL_TI_SCI_FW_ID	35
#define SA2UL_TI_SCI_FW_RGN_ID	0
#elif defined(PLATFORM_FLAVOR_am62x) || \
	defined(PLATFORM_FLAVOR_am62ax) || \
	defined(PLATFORM_FLAVOR_am62px)
#define SA2UL_BASE		0x40900000
#define SA2UL_TI_SCI_DEV_ID	-1
#define SA2UL_TI_SCI_FW_ID	66
#define SA2UL_TI_SCI_FW_RGN_ID	1
#elif !defined(CFG_WITH_SOFTWARE_PRNG)
/*
 * If we got here we're trying to build a hardware based RNG driver
 * but are missing some crticial definitions. This is usually because
 * we're using the wrong platform flavor.
 */
#error "Unknown platform flavor! No SA2UL_BASE address is defined"
#endif
#define SA2UL_REG_SIZE		0x1000

/* RNG */
#define RNG_BASE		(SA2UL_BASE + 0x10000)
#define RNG_REG_SIZE		0x1000
#if defined(PLATFORM_FLAVOR_am62x) || \
	defined(PLATFORM_FLAVOR_am62ax) || \
	defined(PLATFORM_FLAVOR_am62px)
#define RNG_TI_SCI_FW_RGN_ID	2
#else
#define RNG_TI_SCI_FW_RGN_ID	3
#endif

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#endif /*PLATFORM_CONFIG_H*/
