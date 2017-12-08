/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef SUNXI_UART_H
#define SUNXI_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

struct sunxi_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void sunxi_uart_init(struct sunxi_uart_data *pd, paddr_t base);

#endif /*SUNXI_UART_H*/

