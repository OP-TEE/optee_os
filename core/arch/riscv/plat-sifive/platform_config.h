/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025 SiFive, Inc
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <riscv.h>

/* SiFive UART */
#define CONSOLE_UART_BASE	0x10010000
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	0

#define PLAT_THREAD_EXCP_FOREIGN_INTR	\
	(CSR_XIE_EIE | CSR_XIE_TIE | CSR_XIE_SIE)
#define PLAT_THREAD_EXCP_NATIVE_INTR	(0)

#endif /*PLATFORM_CONFIG_H*/
