/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 */

#ifndef DRIVERS_STM32_GPIO_H
#define DRIVERS_STM32_GPIO_H

#include <assert.h>
#include <drivers/pinctrl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct pinctrl_state;
struct stm32_pinctrl;

/*
 * Save pinctrl instances defined in DT node: identifiers and power states
 *
 * @fdt: device tree
 * @node: device node in the device tree
 * @pinctrl: NULL or pointer to array of struct stm32_pinctrl
 * @count: number of elements pointed by argument cfg
 *
 * Return the number of pinctrl instances found or a negative value on error.
 *
 * When @count is 0, @pinctrl may be NULL. The function will return only the
 * number of pinctrl instances found in the device tree for the target
 * device node.
 *
 * If more instances than @count are found then the function returns the
 * effective number of pincltr instance found in the node but fills
 * output array @pinctrl only for the input @count first entries.
 */
int stm32_pinctrl_fdt_get_pinctrl(void *fdt, int node,
				  struct stm32_pinctrl *pinctrl, size_t count);

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
 * Get the number of GPIO pins supported by a target GPIO bank
 *
 * @fdt: device tree reference
 * @pinctrl_node: pinctrl node which GPIO bank node belongs to
 * @bank: target GPIO bank ID
 * Return number of GPIO pins (>= 0) or a negative value on error
 */
int stm32_get_gpio_count(void *fdt, int pinctrl_node, unsigned int bank);

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
static inline
void stm32_pinctrl_set_secure_cfg(struct pinctrl_state *pinctrl __maybe_unused,
				  bool secure __unused)
{
	assert(!pinctrl);
}

static inline
void stm32_gpio_pinctrl_bank_pin(struct pinctrl_state *p __unused,
				 unsigned int *bank __unused,
				 unsigned int *pin __unused,
				 unsigned int *count __maybe_unused)
{
	assert(!count);
}
#endif /*CFG_STM32_GPIO*/
#endif /*DRIVERS_STM32_GPIO_H*/
