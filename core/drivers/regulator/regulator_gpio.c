// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, STMicroelectronics
 */

#include <assert.h>
#include <compiler.h>
#include <drivers/gpio.h>
#include <drivers/regulator.h>
#include <dt-bindings/gpio/gpio.h>
#include <kernel/delay.h>
#include <libfdt.h>
#include <trace.h>

static_assert(GPIO_LEVEL_HIGH == 1 && GPIO_LEVEL_LOW == 0);

/*
 * struct regulator_gpio - GPIO controlled regulator
 * @regulator: Preallocated regulator instance
 * @enable_gpio: GPIO for the enable state of the regulator or NULL if always on
 * @enable_delay: Time (in microsecond) for the regulator to get enabled
 * @voltage_gpio: GPIO for the voltage level selection
 * @levels_desc: Supported voltage levels description
 * @voltage_levels_uv: 2 cells array supported voltage levels, increasing order
 * @voltage_level_high: True if higher voltage level relates to GPIO state 1
 */
struct regulator_gpio {
	struct regulator regulator;
	struct gpio *enable_gpio;
	unsigned int enable_delay;
	struct gpio *voltage_gpio;
	struct regulator_voltages_desc levels_desc;
	int voltage_levels_uv[2];
	bool voltage_level_high;
};

static struct regulator_gpio *regulator_priv(struct regulator *regulator)
{
	return container_of(regulator, struct regulator_gpio, regulator);
}

static TEE_Result regulator_gpio_set_state(struct regulator *regulator,
					   bool enabled)
{
	struct regulator_gpio *regu = regulator_priv(regulator);

	if (regu->enable_gpio) {
		if (enabled) {
			gpio_set_value(regu->enable_gpio, GPIO_LEVEL_HIGH);
			if (regu->enable_delay)
				udelay(regu->enable_delay);
		} else {
			gpio_set_value(regu->enable_gpio, GPIO_LEVEL_LOW);
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result regulator_gpio_read_state(struct regulator *regulator,
					    bool *enabled)
{
	struct regulator_gpio *regu = regulator_priv(regulator);

	if (regu->enable_gpio)
		*enabled = gpio_get_value(regu->enable_gpio);
	else
		*enabled = true;

	return TEE_SUCCESS;
}

static TEE_Result regulator_gpio_set_voltage(struct regulator *regulator,
					     int level_uv)
{
	struct regulator_gpio *regu = regulator_priv(regulator);
	enum gpio_level value = GPIO_LEVEL_LOW;

	if (level_uv == regu->voltage_levels_uv[0])
		value = GPIO_LEVEL_LOW;
	else if (level_uv == regu->voltage_levels_uv[1])
		value = GPIO_LEVEL_HIGH;
	else
		return TEE_ERROR_BAD_PARAMETERS;

	if (!regu->voltage_level_high)
		value = !value;

	gpio_set_value(regu->voltage_gpio, value);

	return TEE_SUCCESS;
}

static TEE_Result regulator_gpio_read_voltage(struct regulator *regulator,
					      int *level_uv)
{
	struct regulator_gpio *regu = regulator_priv(regulator);
	enum gpio_level value = gpio_get_value(regu->voltage_gpio);

	if (!regu->voltage_level_high)
		value = !value;

	*level_uv = regu->voltage_levels_uv[value];

	return TEE_SUCCESS;
}

static TEE_Result regulator_gpio_voltages(struct regulator *regulator,
					  struct regulator_voltages_desc **desc,
					  const int **levels)
{
	struct regulator_gpio *regu = regulator_priv(regulator);

	*desc = &regu->levels_desc;
	*levels = regu->voltage_levels_uv;

	return TEE_SUCCESS;
}

static const struct regulator_ops regulator_gpio_ops = {
	.set_state = regulator_gpio_set_state,
	.get_state = regulator_gpio_read_state,
	.set_voltage = regulator_gpio_set_voltage,
	.get_voltage = regulator_gpio_read_voltage,
	.supported_voltages = regulator_gpio_voltages,
};

static TEE_Result get_enable_gpio(const void *fdt, int node,
				  struct regulator_gpio *regu)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	struct gpio *gpio = NULL;

	res = gpio_dt_get_by_index(fdt, node, 0, "enable", &gpio);
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

	gpio_set_direction(gpio, GPIO_DIR_OUT);

	regu->enable_gpio = gpio;

	return TEE_SUCCESS;
}

static TEE_Result get_voltage_level_gpio(const void *fdt, int node,
					 struct regulator_gpio *regu)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const fdt32_t *cuint = NULL;
	struct gpio *gpio = NULL;
	void *gpio_ref = &gpio;
	int level0 = 0;
	int level1 = 0;
	int len = 0;

	res = dt_driver_device_from_node_idx_prop("gpios", fdt, node, 0,
						  DT_DRIVER_GPIO, gpio_ref);
	if (res)
		return res;

	/*
	 * DT bindings allows more than 1 GPIO to control more than
	 * 2 voltage levels. As it's not used so far in known platforms
	 * this implementation is simplified to support only 2 voltage
	 * levels controlled with a single GPIO.
	 */
	if (dt_driver_device_from_node_idx_prop("gpios", fdt, node, 1,
						DT_DRIVER_GPIO, gpio_ref) !=
	    TEE_ERROR_ITEM_NOT_FOUND) {
		EMSG("Multiple GPIOs not supported for level control");
		return TEE_ERROR_GENERIC;
	}

	cuint = fdt_getprop(fdt, node, "states", &len);
	if (!cuint || len != 4 * sizeof(fdt32_t)) {
		EMSG("Node %s expects 2 levels from property \"states\"",
		     fdt_get_name(fdt, node, NULL));
		return TEE_ERROR_GENERIC;
	}

	if (fdt32_to_cpu(*(cuint + 1))) {
		assert(!fdt32_to_cpu(*(cuint + 3)));
		level1 = fdt32_to_cpu(*(cuint));
		level0 = fdt32_to_cpu(*(cuint + 2));
	} else {
		assert(fdt32_to_cpu(*(cuint + 3)) == 1);
		level0 = fdt32_to_cpu(*(cuint));
		level1 = fdt32_to_cpu(*(cuint + 2));
	}

	/* Get the 2 supported levels in increasing order */
	regu->levels_desc.type = VOLTAGE_TYPE_FULL_LIST;
	regu->levels_desc.num_levels = 2;
	if (level0 < level1) {
		regu->voltage_levels_uv[0] = level0;
		regu->voltage_levels_uv[1] = level1;
		regu->voltage_level_high = true;
	} else {
		regu->voltage_levels_uv[0] = level1;
		regu->voltage_levels_uv[1] = level0;
		regu->voltage_level_high = false;
	}

	gpio_set_direction(gpio, GPIO_DIR_OUT);

	regu->voltage_gpio = gpio;

	return TEE_SUCCESS;
}

static TEE_Result regulator_gpio_probe(const void *fdt, int node,
				       const void *compat_data __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct regulator_gpio *regu = NULL;
	struct regu_dt_desc desc = { };
	const char *supply_name = NULL;
	const char *type = NULL;
	char *regu_name = NULL;

	regu_name = (char *)fdt_get_name(fdt, node, NULL);

	type = fdt_getprop(fdt, node, "regulator-type", NULL);
	if (type && strcmp(type, "voltage")) {
		EMSG("Regulator node %s: type \"%s\" not supported",
		     regu_name, type);
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	regu = calloc(1, sizeof(*regu));
	if (!regu) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	res = get_enable_gpio(fdt, node, regu);
	if (res)
		goto err;

	res = get_voltage_level_gpio(fdt, node, regu);
	if (res)
		goto err;

	if (fdt_getprop(fdt, node, "vin-supply", NULL))
		supply_name = "vin";

	desc = (struct regu_dt_desc){
		.name = regu_name,
		.ops = &regulator_gpio_ops,
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

static const struct dt_device_match regulator_gpio_match_table[] = {
	{ .compatible = "regulator-gpio" },
	{ }
};

DEFINE_DT_DRIVER(regulator_gpio_dt_driver) = {
	.name = "regulator-gpio",
	.match_table = regulator_gpio_match_table,
	.probe = regulator_gpio_probe,
};
