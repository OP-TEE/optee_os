/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2019, STMicroelectronics
 *
 * STM32 GPIO driver relies on platform util fiunctions to get base address
 * and clock ID of the GPIO banks. The drvier API allows to retrieve pin muxing
 * configuration for given nodes and load them at runtime. A pin control
 * instance provide an active and a standby configuration. Pin onwer is
 * responsible to load to expected configuration during PM state transitions
 * as STM32 GPIO driver does no register callbacks to the PM framework.
 */

#ifndef __STM32_GPIO_H
#define __STM32_GPIO_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define GPIO_MODE_INPUT		0x0
#define GPIO_MODE_OUTPUT	0x1
#define GPIO_MODE_ALTERNATE	0x2
#define GPIO_MODE_ANALOG	0x3

#define GPIO_OTYPE_PUSH_PULL	0x0
#define GPIO_OTYPE_OPEN_DRAIN	0x1

#define GPIO_OSPEED_LOW		0x0
#define GPIO_OSPEED_MEDIUM	0x1
#define GPIO_OSPEED_HIGH	0x2
#define GPIO_OSPEED_VERY_HIGH	0x3

#define GPIO_PUPD_NO_PULL	0x0
#define GPIO_PUPD_PULL_UP	0x1
#define GPIO_PUPD_PULL_DOWN	0x2

#define GPIO_OD_LEVEL_LOW	0x0
#define GPIO_OD_LEVEL_HIGH	0x1

/*
 * GPIO configuration description structured as single 16bit word
 * for efficient save/restore when GPIO pin suspends or resumes.
 *
 * @mode: One of GPIO_MODE_*
 * @otype: One of GPIO_OTYPE_*
 * @ospeed: One of GPIO_OSPEED_*
 * @pupd: One of GPIO_PUPD_*
 * @od: One of GPIO_OD_*
 * @af: Alternate function numerical ID between 0 and 15
 */
struct gpio_cfg {
	uint16_t mode:		2;
	uint16_t otype:		1;
	uint16_t ospeed:	2;
	uint16_t pupd:		2;
	uint16_t od:		1;
	uint16_t af:		4;
};

/*
 * Descrption of a pin and its 2 states muxing
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: Pin number in the GPIO bank
 * @active_cfg: Configuratioh in active state
 * @standby_cfg: Configuratioh in standby state
 */
struct stm32_pinctrl {
	uint8_t bank;
	uint8_t pin;
	struct gpio_cfg active_cfg;
	struct gpio_cfg standby_cfg;
};

/*
 * Apply series of pin muxing configuration, active state and standby state
 *
 * @pinctrl: array of pinctrl references
 * @count: Number of entries in @pinctrl
 */
void stm32_pinctrl_load_active_cfg(struct stm32_pinctrl *pinctrl, size_t cnt);
void stm32_pinctrl_load_standby_cfg(struct stm32_pinctrl *pinctrl, size_t cnt);

/*
 * Save the current pin configuration as the standby state for a pin series
 *
 * @pinctrl: array of pinctrl references
 * @count: Number of entries in @pinctrl
 */
void stm32_pinctrl_store_standby_cfg(struct stm32_pinctrl *pinctrl, size_t cnt);

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

/*
 * Set target output GPIO pin to high or low level
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: GPIO pin position in the GPIO bank
 * @high: 1 to set GPIO to high level, 0 to set to GPIO low level
 */
void stm32_gpio_set_output_level(unsigned int bank, unsigned int pin, int high);

/*
 * Set output GPIO pin referenced by @pinctrl to high or low level
 *
 * @pinctrl: Reference to pinctrl
 * @high: 1 to set GPIO to high level, 0 to set to GPIO low level
 */
static inline void stm32_pinctrl_set_gpio_level(struct stm32_pinctrl *pinctrl,
						int high)
{
	stm32_gpio_set_output_level(pinctrl->bank, pinctrl->pin, high);
}

/*
 * Get input GPIO pin current level, high or low
 *
 * @bank: GPIO bank identifier as assigned by the platform
 * @pin: GPIO pin position in the GPIO bank
 * Return 1 if GPIO level is high, 0 if it is low
 */
int stm32_gpio_get_input_level(unsigned int bank, unsigned int pin);

/*
 * Set target output GPIO pin to high or low level
 *
 * @pinctrl: Reference to pinctrl
 * Return 1 if GPIO level is high, 0 if it is low
 */
static inline int stm32_pinctrl_get_gpio_level(struct stm32_pinctrl *pinctrl)
{
	return stm32_gpio_get_input_level(pinctrl->bank, pinctrl->pin);
}

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
#else
static inline void stm32_gpio_set_secure_cfg(unsigned int bank __unused,
					     unsigned int pin __unused,
					     bool secure __unused)
{
	assert(0);
}
#endif

/*
 * Get the number of GPIO pins supported by a target GPIO bank
 *
 * @fdt: device tree reference
 * @pinctrl_node: pinctrl node which GPIO bank node belongs to
 * @bank: target GPIO bank ID
 * Return number of GPIO pins (>= 0) or a negative value on error
 */
int stm32_get_gpio_count(void *fdt, int pinctrl_node, unsigned int bank);

#endif /*__STM32_GPIO_H*/
