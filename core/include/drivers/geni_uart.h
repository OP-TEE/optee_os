/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Linaro Limited
 */
#ifndef __DRIVERS_GENI_UART_H
#define __DRIVERS_GENI_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

#define GENI_UART_REG_SIZE 0x4000

struct geni_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void geni_uart_init(struct geni_uart_data *pd, paddr_t base);

#endif /* __DRIVERS_GENI_UART_H */

