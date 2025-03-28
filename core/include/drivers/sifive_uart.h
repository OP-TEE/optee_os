/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025 SiFive, Inc
 */
#ifndef __DRIVERS_SIFIVE_UART_H
#define __DRIVERS_SIFIVE_UART_H

#include <drivers/serial.h>
#include <mm/core_memprot.h>
#include <types_ext.h>

#define SIFIVE_UART_REG_SIZE	0x1000

struct sifive_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void sifive_uart_init(struct sifive_uart_data *pd, paddr_t base,
		      uint32_t uart_clk, uint32_t baud_rate);

#endif /* __DRIVERS_SIFIVE_UART_H */
