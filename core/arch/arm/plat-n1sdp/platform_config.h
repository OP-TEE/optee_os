/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Arm Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <stdint.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

 /* N1SDP topology related constants */
#define N1SDP_MAX_CPUS_PER_CLUSTER	U(2)
#define PLAT_ARM_CLUSTER_COUNT		U(2)
#define PLAT_N1SDP_CHIP_COUNT		U(2)
#define N1SDP_MAX_CLUSTERS_PER_CHIP	U(2)
#define N1SDP_MAX_PE_PER_CPU		U(1)

#define PLATFORM_CORE_COUNT		(PLAT_N1SDP_CHIP_COUNT *	\
					PLAT_ARM_CLUSTER_COUNT *	\
					N1SDP_MAX_CPUS_PER_CLUSTER *	\
					N1SDP_MAX_PE_PER_CPU)

#define GIC_BASE		0x2c010000

#define UART1_BASE		0x1C0A0000
#define UART1_CLK_IN_HZ		24000000  /* 24MHz */

#define CONSOLE_UART_BASE	UART1_BASE
#define CONSOLE_UART_CLK_IN_HZ	UART1_CLK_IN_HZ

#define DRAM0_BASE		0x80000000
#define DRAM0_SIZE		0x80000000

#define GICD_BASE		0x30000000
#define GICC_BASE		0x2C000000
#define GICR_BASE		0x300C0000

#ifndef UART_BAUDRATE
#define UART_BAUDRATE		115200
#endif
#ifndef CONSOLE_BAUDRATE
#define CONSOLE_BAUDRATE	UART_BAUDRATE
#endif

#endif /*PLATFORM_CONFIG_H*/
