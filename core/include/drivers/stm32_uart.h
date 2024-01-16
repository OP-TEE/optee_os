/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_UART_H
#define __DRIVERS_STM32_UART_H

#include <drivers/clk.h>
#include <drivers/pinctrl.h>
#include <drivers/serial.h>
#include <io.h>
#include <types_ext.h>
#include <stdbool.h>

struct stm32_uart_pdata {
	struct io_pa_va base;
	struct serial_chip chip;
	bool secure;
	struct clk *clock;
	struct pinctrl_state *pinctrl;
	struct pinctrl_state *pinctrl_sleep;
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

#endif /*__DRIVERS_STM32_UART_H*/
