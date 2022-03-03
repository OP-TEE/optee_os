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

#define SCU_BASE        0x01800000
#if defined(PLATFORM_FLAVOR_j721e)
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
#if defined(PLATFORM_FLAVOR_am65x) || defined(PLATFORM_FLAVOR_j721e)
#define SEC_PROXY_DATA_BASE             0x32c00000
#define SEC_PROXY_DATA_SIZE             0x100000
#define SEC_PROXY_SCFG_BASE             0x32800000
#define SEC_PROXY_SCFG_SIZE             0x100000
#define SEC_PROXY_RT_BASE               0x32400000
#define SEC_PROXY_RT_SIZE               0x100000
#define SEC_PROXY_RESPONSE_THREAD       6
#define SEC_PROXY_REQUEST_THREAD        7
#else
#define SEC_PROXY_DATA_BASE             0x4d000000
#define SEC_PROXY_DATA_SIZE             0x80000
#define SEC_PROXY_SCFG_BASE             0x4a400000
#define SEC_PROXY_SCFG_SIZE             0x80000
#define SEC_PROXY_RT_BASE               0x4a600000
#define SEC_PROXY_RT_SIZE               0x80000
#define SEC_PROXY_RESPONSE_THREAD       10
#define SEC_PROXY_REQUEST_THREAD        11
#endif
#define OPTEE_HOST_ID                   11
#define SEC_PROXY_TIMEOUT_US            1000000
#define GICC_BASE       (SCU_BASE + GICC_OFFSET)
#define GICD_BASE       (SCU_BASE + GICD_OFFSET)

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#endif /*PLATFORM_CONFIG_H*/
