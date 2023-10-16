/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 */

#ifndef __DRIVERS_GPIO_H
#define __DRIVERS_GPIO_H

#include <assert.h>
#include <dt-bindings/gpio/gpio.h>
#include <kernel/dt_driver.h>
#include <stdint.h>
#include <tee_api_types.h>

/**
 * GPIO_DT_DECLARE - Declare a GPIO controller driver with a single
 * device tree compatible string.
 *
 * @__name: GPIO controller driver name
 * @__compat: Compatible string
 * @__probe: GPIO controller probe function
 */
#define GPIO_DT_DECLARE(__name, __compat, __probe) \
	static const struct dt_device_match __name ## _match_table[] = { \
		{ .compatible = __compat }, \
		{ } \
	}; \
	DEFINE_DT_DRIVER(__name ## _dt_driver) = { \
		.name = # __name, \
		.type = DT_DRIVER_GPIO, \
		.match_table = __name ## _match_table, \
		.probe = __probe, \
	}

enum gpio_dir {
	GPIO_DIR_OUT,
	GPIO_DIR_IN
};

enum gpio_level {
	GPIO_LEVEL_LOW,
	GPIO_LEVEL_HIGH
};

enum gpio_interrupt {
	GPIO_INTERRUPT_DISABLE,
	GPIO_INTERRUPT_ENABLE
};

struct gpio;
struct gpio_ops;

struct gpio_chip {
	const struct gpio_ops *ops;
};

struct gpio_ops {
	/* Get GPIO direction current configuration */
	enum gpio_dir (*get_direction)(struct gpio_chip *chip,
				       unsigned int gpio_pin);
	/* Set GPIO direction configuration */
	void (*set_direction)(struct gpio_chip *chip, unsigned int gpio_pin,
			      enum gpio_dir direction);
	/* Get GPIO current level */
	enum gpio_level (*get_value)(struct gpio_chip *chip,
				     unsigned int gpio_pin);
	/* Set GPIO level */
	void (*set_value)(struct gpio_chip *chip, unsigned int gpio_pin,
			  enum gpio_level value);
	/* Get GPIO interrupt state */
	enum gpio_interrupt (*get_interrupt)(struct gpio_chip *chip,
					     unsigned int gpio_pin);
	/* Enable or disable a GPIO interrupt */
	void (*set_interrupt)(struct gpio_chip *chip, unsigned int gpio_pin,
			      enum gpio_interrupt enable_disable);
	/* Release GPIO resources */
	void (*put)(struct gpio_chip *chip, struct gpio *gpio);
};

/*
 * struct gpio - GPIO pin description
 * @chip: GPIO controller chip reference
 * @dt_flags: Pin boolean properties set from DT node
 * @pin: Pin number in GPIO controller
 */
struct gpio {
	struct gpio_chip *chip;
	uint32_t dt_flags;
	unsigned int pin;
};

static inline bool gpio_ops_is_valid(const struct gpio_ops *ops)
{
	return ops->set_direction && ops->get_direction && ops->get_value &&
	       ops->set_value;
}

static inline void gpio_set_direction(struct gpio *gpio, enum gpio_dir dir)
{
	gpio->chip->ops->set_direction(gpio->chip, gpio->pin, dir);
}

static inline enum gpio_dir gpio_get_direction(struct gpio *gpio)
{
	return gpio->chip->ops->get_direction(gpio->chip, gpio->pin);
}

static inline void gpio_set_value(struct gpio *gpio, enum gpio_level value)
{
	if (gpio->dt_flags & GPIO_ACTIVE_LOW)
		value = !value;

	gpio->chip->ops->set_value(gpio->chip, gpio->pin, value);
}

static inline enum gpio_level gpio_get_value(struct gpio *gpio)
{
	enum gpio_level value = GPIO_LEVEL_LOW;

	value = gpio->chip->ops->get_value(gpio->chip, gpio->pin);

	if (gpio->dt_flags & GPIO_ACTIVE_LOW)
		value = !value;

	return value;
}

static inline void gpio_put(struct gpio *gpio)
{
	assert(!gpio || (gpio->chip && gpio->chip->ops));

	if (gpio && gpio->chip->ops->put)
		gpio->chip->ops->put(gpio->chip, gpio);
}

#if defined(CFG_DT) && defined(CFG_DRIVERS_GPIO)
/**
 * gpio_dt_alloc_pin() - Get an allocated GPIO instance from its DT phandle
 *
 * @pargs: Pointer to devicetree description of the GPIO controller to parse
 * @res: Output result code of the operation:
 *	TEE_SUCCESS in case of success
 *	TEE_ERROR_DEFER_DRIVER_INIT if GPIO controller is not initialized
 *	Any TEE_Result compliant code in case of error.
 *
 * Returns a struct gpio pointer pointing to a GPIO instance matching
 * the devicetree description or NULL if invalid description in which case
 * @res provides the error code.
 */
TEE_Result gpio_dt_alloc_pin(struct dt_pargs *pargs, struct gpio **gpio);

/**
 * gpio_dt_get_by_index() - Get a GPIO controller at a specific index in
 * 'gpios' property
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the subnode containing a 'gpios' property
 * @index: GPIO pin index in '*-gpios' property
 * @gpio_name: Name of the GPIO pin
 * @gpio: Output GPIO pin reference upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if GPIO controller is not initialized
 * Return a TEE_Result compliant code in case of error
 */
TEE_Result gpio_dt_get_by_index(const void *fdt, int nodeoffset,
				unsigned int index, const char *gpio_name,
				struct gpio **gpio);
#else
static inline TEE_Result gpio_dt_get_by_index(const void *fdt __unused,
					      int nodeoffset __unused,
					      unsigned int index  __unused,
					      const char *gpio_name  __unused,
					      struct gpio **gpio __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result gpio_dt_alloc_pin(struct dt_pargs *pargs __unused,
					   struct gpio **gpio __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*CFG_DT*/

/**
 * gpio_dt_get_func - Typedef of function to get GPIO instance from
 * devicetree properties
 *
 * @pargs: Pointer to GPIO phandle and its argument in the FDT
 * @data: Pointer to the data given at gpio_dt_register_provider() call
 * @res: Output result code of the operation:
 *	TEE_SUCCESS in case of success
 *	TEE_ERROR_DEFER_DRIVER_INIT if GPIO controller is not initialized
 *	Any TEE_Result compliant code in case of error.
 *
 * Returns a struct GPIO pointer pointing to a GPIO instance matching
 * the devicetree description or NULL if invalid description in which case
 * @res provides the error code.
 */
typedef TEE_Result (*gpio_dt_get_func)(struct dt_pargs *pargs, void *data,
				       struct gpio **out_gpio);

/**
 * gpio_dt_register_provider() - Register a GPIO controller provider
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the GPIO controller
 * @get_dt_gpio: Callback to match the GPIO controller with a struct gpio
 * @data: Opaque reference which will be passed to the get_dt_gpio callback
 * Returns TEE_Result value
 */
static inline TEE_Result gpio_register_provider(const void *fdt, int nodeoffset,
						gpio_dt_get_func get_dt_gpio,
						void *data)
{
	return dt_driver_register_provider(fdt, nodeoffset,
					   (get_of_device_func)get_dt_gpio,
					   data, DT_DRIVER_GPIO);
}

#endif	/* __DRIVERS_GPIO_H */
