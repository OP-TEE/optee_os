/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_GPIO_H
#define __DRIVERS_STM32_GPIO_H

#include <assert.h>
#include <drivers/gpio.h>
#include <drivers/pinctrl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct pinctrl_state;
struct stm32_pinctrl;

#ifdef CFG_STM32_GPIO
/*
 * Get the bank and pin indices related to a pin control state
 * @pinctrl: Pinctrl state
 * @bank: Output bank indices array or NULL
 * @pin: Output pin indices array or NULL
 * @count: [in] Number of cells of @bank and @pin, [out] pin count in @pinctrl
 */
void stm32_gpio_pinctrl_bank_pin(struct pinctrl_state *pinctrl,
				 unsigned int *bank, unsigned int *pin,
				 unsigned int *count);

/*
 * stm32_gpio_chip_bank_id() - Get the GPIO bank ID associated to a chip
 * @chip: GPIO chip associated to the bank
 */
unsigned int stm32_gpio_chip_bank_id(struct gpio_chip *chip);
#else
static inline void stm32_gpio_pinctrl_bank_pin(struct pinctrl_state *p __unused,
					       unsigned int *bank __unused,
					       unsigned int *pin __unused,
					       unsigned int *count __unused)
{
}

static inline unsigned int __noreturn
stm32_gpio_chip_bank_id(struct gpio_chip *chip __unused)
{
	panic();
}
#endif /*CFG_STM32_GPIO*/
#endif /*__DRIVERS_STM32_GPIO_H*/
