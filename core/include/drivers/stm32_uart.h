/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2018, STMicroelectronics
 */

#ifndef __STM32_UART_H__
#define __STM32_UART_H__

#include <drivers/clk.h>
#include <drivers/serial.h>
#include <drivers/stm32_gpio.h>

struct stm32_uart_pdata {
	struct io_pa_va base;
	struct serial_chip chip;
	bool secure;
	struct clk *clock;
	struct stm32_pinctrl *pinctrl;
	size_t pinctrl_count;
};

/*
 * stm32_uart_init - Initialize a UART serial chip and base address
 * @pd: Output initialized UART platform data
 * @base: UART interface physical base address
 */
void stm32_uart_init(struct stm32_uart_pdata *pd, vaddr_t base);

/*
 * stm32_uart_init_from_dt_node - Initialize a UART instance from a DTB node
 * @fdt: DTB base address
 * @node: Target node offset in the DTB
 * Returns an alloced (malloc) and inited UART platform data on success or NULL
 *
 * This function gets a STM32 UART configuration directives from a DTB node
 * and initializes a UART driver instance.
 * When the DTB specifies that the device is disabled, the function returns
 * NULL. Other issues panic the sequence.
 */
struct stm32_uart_pdata *stm32_uart_init_from_dt_node(void *fdt, int node);

#endif /*__STM32_UART_H__*/
