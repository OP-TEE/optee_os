// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Microchip
 */

#include <drivers/gpio.h>
#include <libfdt.h>
#include <stdio.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <util.h>

/* gpio suffixes used for device tree lookup */
static const char * const gpio_suffixes[] = { "gpios", "gpio" };

TEE_Result gpio_dt_alloc_pin(struct dt_pargs *pargs, struct gpio **out_gpio)
{
	struct gpio *gpio = NULL;

	if (pargs->args_count != 2)
		return TEE_ERROR_BAD_PARAMETERS;

	gpio = calloc(1, sizeof(struct gpio));
	if (!gpio)
		return TEE_ERROR_OUT_OF_MEMORY;

	gpio->pin = pargs->args[0];
	gpio->dt_flags = pargs->args[1];

	*out_gpio = gpio;

	return TEE_SUCCESS;
}

TEE_Result gpio_dt_get_by_index(const void *fdt, int nodeoffset,
				unsigned int index, const char *gpio_name,
				struct gpio **gpio)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	char prop_name[32]; /* 32 is max size of property name in DT */
	void *out_gpio = NULL;
	unsigned int i = 0;

	/* Try GPIO properties "foo-gpios" and "foo-gpio" */
	for (i = 0; i < ARRAY_SIZE(gpio_suffixes); i++) {
		if (gpio_name)
			snprintf(prop_name, sizeof(prop_name), "%s-%s",
				 gpio_name, gpio_suffixes[i]);
		else
			snprintf(prop_name, sizeof(prop_name), "%s",
				 gpio_suffixes[i]);

		res = dt_driver_device_from_node_idx_prop(prop_name, fdt,
							  nodeoffset,
							  index, DT_DRIVER_GPIO,
							  &out_gpio);

		if (res != TEE_ERROR_ITEM_NOT_FOUND)
			break;
	}

	if (!res)
		*gpio = out_gpio;

	return res;
}
