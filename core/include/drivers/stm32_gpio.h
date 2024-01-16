/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_GPIO_H
#define __DRIVERS_STM32_GPIO_H

#include <assert.h>
#include <drivers/pinctrl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct pinctrl_state;
struct stm32_pinctrl;

#ifdef CFG_STM32_GPIO
/*
 * Configure pin muxing access permission: can be secure or not
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: Pin number in the GPIO bank
 * @secure: True if pin is secure, false otherwise
 */
void stm32_gpio_set_secure_cfg(unsigned int bank, unsigned int pin,
			       bool secure);

/*
 * Configure pin muxing access permission: can be secure or not
 *
 * @pinctrl: Pin control state where STM32_GPIO pin are to configure
 * @secure: True if pin is secure, false otherwise
 */
void stm32_pinctrl_set_secure_cfg(struct pinctrl_state *pinctrl, bool secure);

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
#else
static inline void
stm32_pinctrl_set_secure_cfg(struct pinctrl_state *pinctrl __unused,
			     bool secure __unused)
{
}

static inline void stm32_gpio_pinctrl_bank_pin(struct pinctrl_state *p __unused,
					       unsigned int *bank __unused,
					       unsigned int *pin __unused,
					       unsigned int *count __unused)
{
}
#endif /*CFG_STM32_GPIO*/
#endif /*__DRIVERS_STM32_GPIO_H*/
