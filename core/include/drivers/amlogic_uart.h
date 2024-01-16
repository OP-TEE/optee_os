/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef __DRIVERS_AMLOGIC_UART_H
#define __DRIVERS_AMLOGIC_UART_H

#include <types_ext.h>
#include <drivers/serial.h>

struct amlogic_uart_data {
	struct io_pa_va base;
	struct serial_chip chip;
};

void amlogic_uart_init(struct amlogic_uart_data *pd, paddr_t base);

#endif /* __DRIVERS_AMLOGIC_UART_H */
