// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022-2023, STMicroelectronics
 */

#include <compiler.h>
#include <drivers/gpio.h>
#include <drivers/regulator.h>
#include <dt-bindings/gpio/gpio.h>
#include <kernel/delay.h>
#include <kernel/dt_driver.h>
#include <libfdt.h>
#include <tee_api_types.h>
#include <trace.h>

static_assert(GPIO_LEVEL_HIGH == 1 && GPIO_LEVEL_LOW == 0);

/*
 * struct regulator_gpio - GPIO controlled regulator
 * @regulator: Preallocated regulator instance
 * @enable_gpio: GPIO for the enable state of the regulator or NULL if always on
 * @enable_delay: Time (in microsecond) for the regulator to get enabled
 * @off_on_delay: Min time (in microsecond) between enable and disable request
 * @off_on_us: Timestamp of the last disable request
 */
struct regulator_fixed {
	struct regulator regulator;
	struct gpio *enable_gpio;
	unsigned int enable_delay;
	unsigned int off_on_delay;
	uint64_t off_on_us;
};

static struct regulator_fixed *regulator_priv(struct regulator *regulator)
{
	return container_of(regulator, struct regulator_fixed, regulator);
}

static TEE_Result fixed_set_state(struct regulator *regulator, bool enabled)
{
	struct regulator_fixed *regu = regulator_priv(regulator);

	if (regu->enable_gpio) {
		if (enabled) {
			while (!timeout_elapsed(regu->off_on_us))
				udelay(1);
			gpio_set_value(regu->enable_gpio, GPIO_LEVEL_HIGH);
			udelay(regu->enable_delay);
		} else {
			regu->off_on_us = timeout_init_us(regu->off_on_delay);
			gpio_set_value(regu->enable_gpio, GPIO_LEVEL_LOW);
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result fixed_get_state(struct regulator *regulator, bool *enabled)
{
	struct regulator_fixed *regu = regulator_priv(regulator);

	if (regu->enable_gpio)
		*enabled = gpio_get_value(regu->enable_gpio);
	else
		*enabled = true;

	return TEE_SUCCESS;
}

static const struct regulator_ops fixed_regulator_ops = {
	.set_state = fixed_set_state,
	.get_state = fixed_get_state,
};

static TEE_Result get_enable_gpio(const void *fdt, int node,
				  struct regulator_fixed *regu)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	struct gpio *gpio = NULL;
	void *gpio_ref = &gpio;

	res = dt_driver_device_from_node_idx_prop("gpios", fdt, node, 0,
						  DT_DRIVER_GPIO, gpio_ref);
	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = dt_driver_device_from_node_idx_prop("gpio", fdt, node, 0,
							  DT_DRIVER_GPIO,
							  gpio_ref);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		regu->enable_gpio = NULL;

		return TEE_SUCCESS;
	}
	if (res)
		return res;

	/* Override active level phandle flag, as per DT bindings */
	if (dt_have_prop(fdt, node, "enable-active-high"))
		gpio->dt_flags &= ~GPIO_ACTIVE_LOW;
	else
		gpio->dt_flags |= GPIO_ACTIVE_LOW;

	/* Override open drain/open source phandle flag, as per DT bindings */
	if (dt_have_prop(fdt, node, "gpio-open-drain"))
		gpio->dt_flags |= GPIO_LINE_OPEN_DRAIN;
	else
		gpio->dt_flags &= ~GPIO_LINE_OPEN_DRAIN;

	cuint = fdt_getprop(fdt, node, "startup-delay-us", NULL);
	if (cuint)
		regu->enable_delay = fdt32_to_cpu(*cuint);

	cuint = fdt_getprop(fdt, node, "off-on-delay-us", NULL);
	if (cuint)
		regu->off_on_delay = fdt32_to_cpu(*cuint);

	gpio_set_direction(gpio, GPIO_DIR_OUT);

	regu->enable_gpio = gpio;

	return TEE_SUCCESS;
}

static TEE_Result fixed_regulator_probe(const void *fdt, int node,
					const void *compat_data __unused)
{
	struct regulator_fixed *regu = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regu_dt_desc desc = { };
	const char *supply_name = NULL;
	const char *type = NULL;
	char *regu_name = NULL;

	regu_name = (char *)fdt_get_name(fdt, node, NULL);

	type = fdt_getprop(fdt, node, "regulator-type", NULL);
	if (type && strcmp(type, "voltage")) {
		EMSG("Regulator gpio node %s: type %s not supported",
		     regu_name, type);
		return TEE_ERROR_GENERIC;
	}

	regu = calloc(1, sizeof(*regu));
	if (!regu)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = get_enable_gpio(fdt, node, regu);
	if (res)
		goto err;

	if (fdt_getprop(fdt, node, "vin-supply", NULL))
		supply_name = "vin";

	desc = (struct regu_dt_desc){
		.name = regu_name,
		.ops = &fixed_regulator_ops,
		.supply_name = supply_name,
		.regulator = &regu->regulator,
	};

	res = regulator_dt_register(fdt, node, node, &desc);
	if (res) {
		EMSG("Can't register regulator %s: %#"PRIx32, regu_name, res);
		goto err;
	}

	return TEE_SUCCESS;

err:
	free(regu);

	return res;
}

static const struct dt_device_match regulator_match_table[] = {
	{ .compatible = "regulator-fixed" },
	{ }
};

DEFINE_DT_DRIVER(fixed_regulator_dt_driver) = {
	.name = "regulator-fixed",
	.match_table = regulator_match_table,
	.probe = fixed_regulator_probe,
};
