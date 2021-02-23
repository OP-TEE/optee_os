// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2021 NXP
 *
 * Driver for GPIO Controller
 *
 */

#include <assert.h>
#include <drivers/ls_gpio.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#include <mm/core_memprot.h>

static const char * const gpio_controller_map[] = {
	 "/soc/gpio@2300000",
	 "/soc/gpio@2310000",
	 "/soc/gpio@2320000",
	 "/soc/gpio@2330000"
};

/*
 * Get value from GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin from which value needs to be read
 */
static enum gpio_level gpio_get_value(struct gpio_chip *chip,
				      unsigned int gpio_pin)
{
	vaddr_t gpio_data_addr = 0;
	uint32_t data = 0;
	struct ls_gpio_chip_data *gc_data = container_of(chip,
						      struct ls_gpio_chip_data,
						      chip);

	assert(gpio_pin <= MAX_GPIO_PINS);

	gpio_data_addr = gc_data->gpio_base + GPIODAT;
	data = io_read32(gpio_data_addr);

	if (data & PIN_SHIFT(gpio_pin))
		return GPIO_LEVEL_HIGH;
	else
		return GPIO_LEVEL_LOW;
}

/*
 * Set value for GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin to which value needs to be write
 * value:       value needs to be written to the pin
 */
static void gpio_set_value(struct gpio_chip *chip, unsigned int gpio_pin,
			   enum gpio_level value)
{
	vaddr_t gpio_data_addr = 0;
	struct ls_gpio_chip_data *gc_data = container_of(chip,
						      struct ls_gpio_chip_data,
						      chip);

	assert(gpio_pin <= MAX_GPIO_PINS);

	gpio_data_addr = gc_data->gpio_base + GPIODAT;

	if (value == GPIO_LEVEL_HIGH)
		/* if value is high then set pin value */
		io_setbits32(gpio_data_addr, PIN_SHIFT(gpio_pin));
	else
		/* if value is low then clear pin value */
		io_clrbits32(gpio_data_addr, PIN_SHIFT(gpio_pin));
}

/*
 * Get direction from GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin from which direction needs to be read
 */
static enum gpio_dir gpio_get_direction(struct gpio_chip *chip,
					unsigned int gpio_pin)
{
	vaddr_t gpio_dir_addr = 0;
	uint32_t data = 0;
	struct ls_gpio_chip_data *gc_data = container_of(chip,
						      struct ls_gpio_chip_data,
						      chip);

	assert(gpio_pin <= MAX_GPIO_PINS);

	gpio_dir_addr = gc_data->gpio_base + GPIODIR;
	data = io_read32(gpio_dir_addr);

	if (data & PIN_SHIFT(gpio_pin))
		return GPIO_DIR_OUT;
	else
		return GPIO_DIR_IN;
}

/*
 * Set direction for GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin on which direction needs to be set
 * direction:   direction which needs to be set on pin
 */
static void gpio_set_direction(struct gpio_chip *chip, unsigned int gpio_pin,
			       enum gpio_dir direction)
{
	vaddr_t gpio_dir_addr = 0;
	struct ls_gpio_chip_data *gc_data = container_of(chip,
						      struct ls_gpio_chip_data,
						      chip);

	assert(gpio_pin <= MAX_GPIO_PINS);

	gpio_dir_addr = gc_data->gpio_base + GPIODIR;

	if (direction == GPIO_DIR_OUT)
		io_setbits32(gpio_dir_addr, PIN_SHIFT(gpio_pin));
	else
		io_clrbits32(gpio_dir_addr, PIN_SHIFT(gpio_pin));
}

/*
 * Get interrupt from GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin from which interrupt value needs to be read
 */
static enum gpio_interrupt gpio_get_interrupt(struct gpio_chip *chip,
					      unsigned int gpio_pin)
{
	vaddr_t gpio_ier_addr = 0;
	uint32_t data = 0;
	struct ls_gpio_chip_data *gc_data = container_of(chip,
						      struct ls_gpio_chip_data,
						      chip);

	assert(gpio_pin <= MAX_GPIO_PINS);

	gpio_ier_addr = gc_data->gpio_base + GPIOIER;
	data = io_read32(gpio_ier_addr);

	if (data & PIN_SHIFT(gpio_pin))
		return GPIO_INTERRUPT_ENABLE;
	else
		return GPIO_INTERRUPT_DISABLE;
}

/*
 * Set interrupt event for GPIO controller
 * chip:        pointer to GPIO controller chip instance
 * gpio_pin:    pin on which interrupt value needs to be set
 * interrupt:   interrupt valie which needs to be set on pin
 */
static void gpio_set_interrupt(struct gpio_chip *chip, unsigned int gpio_pin,
			       enum gpio_interrupt interrupt)
{
	vaddr_t gpio_ier_addr = 0;
	struct ls_gpio_chip_data *gc_data = container_of(chip,
						      struct ls_gpio_chip_data,
						      chip);

	assert(gpio_pin <= MAX_GPIO_PINS);

	gpio_ier_addr = gc_data->gpio_base + GPIOIER;

	if (interrupt == GPIO_INTERRUPT_ENABLE)
		io_setbits32(gpio_ier_addr, PIN_SHIFT(gpio_pin));
	else
		io_clrbits32(gpio_ier_addr, PIN_SHIFT(gpio_pin));
}

/*
 * Extract information for GPIO Controller from the DTB
 * gpio_data:	GPIO controller chip instance
 */
static TEE_Result get_info_from_device_tree(struct ls_gpio_chip_data *gpio_data)
{
	size_t size = 0;
	int node = 0;
	vaddr_t ctrl_base = 0;
	void *fdt = NULL;

	/*
	 * First get the GPIO Controller base address from the DTB
	 * if DTB present and if the GPIO Controller defined in it.
	 */
	fdt = get_embedded_dt();
	if (!fdt) {
		EMSG("Unable to get the Embedded DTB, GPIO init failed\n");
		return TEE_ERROR_GENERIC;
	}

	node = fdt_path_offset(fdt, gpio_controller_map
			       [gpio_data->gpio_controller]);
	if (node > 0) {
		if (dt_map_dev(fdt, node, &ctrl_base, &size) < 0) {
			EMSG("Unable to get virtual address");
			return TEE_ERROR_GENERIC;
		}
	} else {
		EMSG("Unable to get gpio offset node");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	gpio_data->gpio_base = ctrl_base;

	return TEE_SUCCESS;
}

static const struct gpio_ops ls_gpio_ops = {
	.get_direction = gpio_get_direction,
	.set_direction = gpio_set_direction,
	.get_value = gpio_get_value,
	.set_value = gpio_set_value,
	.get_interrupt = gpio_get_interrupt,
	.set_interrupt = gpio_set_interrupt,
};
DECLARE_KEEP_PAGER(ls_gpio_ops);

TEE_Result ls_gpio_init(struct ls_gpio_chip_data *gpio_data)
{
	TEE_Result status = TEE_ERROR_GENERIC;

	/*
	 * First get the GPIO Controller base address from the DTB,
	 * if DTB present and if the GPIO Controller defined in it.
	 */
	status = get_info_from_device_tree(gpio_data);
	if (status == TEE_SUCCESS) {
		/* set GPIO Input Buffer Enable register */
		io_setbits32(gpio_data->gpio_base + GPIOIBE, UINT32_MAX);

		/* generic GPIO chip handle */
		gpio_data->chip.ops = &ls_gpio_ops;
	} else {
		EMSG("Unable to get info from device tree");
	}

	return status;
}
