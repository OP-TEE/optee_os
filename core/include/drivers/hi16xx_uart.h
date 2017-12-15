/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

/*
 * UART driver for Hisilicon Hi16xx and Phosphor V660 (hip05) SoCs
 */

#ifndef HI16XX_UART_H
#define HI16XX_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

#define HI16XX_UART_REG_SIZE 0xF8

struct hi16xx_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void hi16xx_uart_init(struct hi16xx_uart_data *pd, paddr_t base,
		      uint32_t uart_clk, uint32_t baud_rate);

#endif /* HI16XX_UART_H */
