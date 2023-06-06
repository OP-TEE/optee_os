// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Microchip
 */

#include <assert.h>
#include <drivers/pinctrl.h>
#include <libfdt.h>
#include <stdio.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <util.h>

static const char * const pin_modes[PINCTRL_DT_PROP_MAX] = {
	[PINCTRL_DT_PROP_BIAS_DISABLE] = "bias-disable",
	[PINCTRL_DT_PROP_BIAS_PULL_UP] = "bias-pull-up",
	[PINCTRL_DT_PROP_BIAS_PULL_DOWN] = "bias-pull-down",
};

TEE_Result pinctrl_parse_dt_pin_modes(const void *fdt, int node,
				      bitstr_t **modes)
{
	unsigned int i = 0;
	bitstr_t *modes_ptr = NULL;

	modes_ptr = bit_alloc(PINCTRL_DT_PROP_MAX);
	if (!modes_ptr)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < ARRAY_SIZE(pin_modes); i++)
		if (fdt_getprop(fdt, node, pin_modes[i], NULL))
			bit_set(modes_ptr, i);

	*modes = modes_ptr;

	return TEE_SUCCESS;
}

TEE_Result pinctrl_apply_state(struct pinctrl_state *state)
{
	unsigned int i = 0;
	struct pinconf *conf = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	for (i = 0; i < state->conf_count; i++) {
		conf = state->confs[i];

		res = conf->ops->conf_apply(conf);
		if (res) {
			EMSG("Failed to apply pin conf");
			return res;
		}
	}

	return TEE_SUCCESS;
}

void pinctrl_free_state(struct pinctrl_state *state)
{
	unsigned int i = 0;

	for (i = 0; i < state->conf_count; i++)
		state->confs[i]->ops->conf_free(state->confs[i]);

	free(state);
}

TEE_Result pinctrl_get_state_by_idx(const void *fdt, int nodeoffset,
				    unsigned int pinctrl_index,
				    struct pinctrl_state **state_ret)
{
	int bw = 0;
	unsigned int conf_id = 0;
	const uint32_t *prop = NULL;
	unsigned int conf_count = 0;
	/* Enough char to hold "pinctrl-<max_int>" */
	char prop_name[8 + 20 + 1] = { };
	struct pinctrl_state *state = NULL;
	TEE_Result res = TEE_ERROR_GENERIC;

	bw = snprintf(prop_name, sizeof(prop_name), "pinctrl-%d",
		      pinctrl_index);
	if (bw >= (int)sizeof(prop_name))
		return TEE_ERROR_OVERFLOW;

	prop = fdt_getprop(fdt, nodeoffset, prop_name, (int *)&conf_count);
	if (!prop)
		return TEE_ERROR_ITEM_NOT_FOUND;

	conf_count /= sizeof(uint32_t);
	state = calloc(1, sizeof(struct pinctrl_state) +
			  conf_count * sizeof(struct pinconf *));
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->conf_count = conf_count;
	for (conf_id = 0; conf_id < conf_count; conf_id++) {
		void *pinconf = NULL;

		res = dt_driver_device_from_node_idx_prop(prop_name, fdt,
							  nodeoffset, conf_id,
							  DT_DRIVER_PINCTRL,
							  &pinconf);
		if (res) {
			free(state);
			return res;
		}

		state->confs[conf_id] = pinconf;
	}

	*state_ret = state;

	return TEE_SUCCESS;
}

TEE_Result pinctrl_get_state_by_name(const void *fdt, int nodeoffset,
				     const char *name,
				     struct pinctrl_state **state)
{
	int pinctrl_index = 0;

	if (!name)
		name = "default";

	pinctrl_index = fdt_stringlist_search(fdt, nodeoffset, "pinctrl-names",
					      name);
	if (pinctrl_index < 0) {
		*state = NULL;
		if (pinctrl_index == -FDT_ERR_NOTFOUND)
			return TEE_ERROR_ITEM_NOT_FOUND;
		else
			return TEE_ERROR_GENERIC;
	}

	return pinctrl_get_state_by_idx(fdt, nodeoffset, pinctrl_index, state);
}
