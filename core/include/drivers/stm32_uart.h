/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#ifndef __STM32_UART_H__
#define __STM32_UART_H__

#include <drivers/serial.h>

struct console_pdata {
	struct io_pa_va base;
	struct serial_chip chip;
};

void stm32_uart_init(struct console_pdata *pd, vaddr_t base);

#endif /*__STM32_UART_H__*/
