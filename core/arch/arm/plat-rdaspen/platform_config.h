/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2025, Arm Limited
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT			            64

/* UART constants */
#define UART1_BASE			                UL(0x1a410000)
#define CONSOLE_UART_BASE		            UART1_BASE
#define UART_BAUDRATE			            115200
#define CONSOLE_BAUDRATE		            UART_BAUDRATE
#define CONSOLE_UART_CLK_IN_HZ		        UL(24000000)

/* DRAM constants */
#define DRAM0_BASE		                    UL(0x80000000)
#define DRAM0_SIZE		                    UL(0x80000000)

/* GIC related constants */
#define GICD_BASE		                    UL(0x20000000)
#define GICR_BASE		                    UL(0x200C0000)
#define GICR_SIZE		                    UL(0xF00000)

/* RD-Aspen topology related constants */
#define RDASPEN_MAX_CPUS_PER_CLUSTER		U(4)
#define RDASPEN_MAX_PE_PER_CPU			    U(1)

#endif /* PLATFORM_CONFIG_H */
