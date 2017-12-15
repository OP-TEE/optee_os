/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#ifndef SERIAL8250_UART_H
#define SERIAL8250_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

#define SERIAL8250_UART_REG_SIZE 0x20

struct serial8250_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void serial8250_uart_init(struct serial8250_uart_data *pd, paddr_t base,
			  uint32_t uart_clk, uint32_t baud_rate);

#endif /* SERIAL8250_UART_H */

