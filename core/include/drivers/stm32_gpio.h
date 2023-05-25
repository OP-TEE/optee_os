/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2017-2023, STMicroelectronics
 */

#ifndef DRIVERS_STM32_GPIO_H
#define DRIVERS_STM32_GPIO_H

#include <assert.h>
#include <compiler.h>
#include <drivers/pinctrl.h>
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

struct pinctrl_state;

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
 * @cfg: Pin configuration
 * @active_cfg: Configuration in active state
 * @standby_cfg: Configuration in standby state
 */
struct stm32_pinctrl {
	uint8_t bank;
	uint8_t pin;
	struct gpio_cfg cfg;
};

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
