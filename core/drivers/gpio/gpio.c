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

static char *gpio_get_dt_prop_name(const char *gpio_name)
{
	int ret = 0;
	char *prop_name = NULL;
	size_t max_len = strlen(gpio_name) + strlen("-gpios") + 1;

	prop_name = calloc(1, max_len);
	if (!prop_name)
		return NULL;

	ret = snprintf(prop_name, max_len, "%s-gpios", gpio_name);
	if (ret < 0 || (size_t)ret >= max_len) {
		free(prop_name);
		return NULL;
	}

	return prop_name;
}

TEE_Result gpio_dt_get_by_index(const void *fdt, int nodeoffset,
				unsigned int index, const char *gpio_name,
				struct gpio **gpio)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	char *prop_name = NULL;
	void *out_gpio = NULL;

	prop_name = gpio_get_dt_prop_name(gpio_name);
	if (!prop_name)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = dt_driver_device_from_node_idx_prop(prop_name, fdt, nodeoffset,
						  index, DT_DRIVER_GPIO,
						  &out_gpio);
	free(prop_name);
	if (!res)
		*gpio = out_gpio;

	return res;
}
