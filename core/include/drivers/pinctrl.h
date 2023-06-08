/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022-2023, Microchip
 */

#ifndef __DRIVERS_PINCTRL_H
#define __DRIVERS_PINCTRL_H

#include <bitstring.h>
#include <kernel/dt_driver.h>
#include <sys/queue.h>
#include <tee_api_types.h>

enum pinctrl_dt_prop {
	/* Property "bias-disable" found in pinctrl node */
	PINCTRL_DT_PROP_BIAS_DISABLE,
	/* Property "bias-pull-up" found in pinctrl node */
	PINCTRL_DT_PROP_BIAS_PULL_UP,
	/* Property "bias-pull-down" found in pinctrl node */
	PINCTRL_DT_PROP_BIAS_PULL_DOWN,
	/* Terminal ID */
	PINCTRL_DT_PROP_MAX
};

/*
 * struct pinconf - Pinctrl device
 * @ops: Operation handlers
 * @priv: Pinctrl driver private data
 */
struct pinconf {
	const struct pinctrl_ops *ops;
	void *priv;
};

/*
 * struct pinctrl_state - Pinctrl configuration state
 * @conf_count: Number of cells in @confs
 * @confs: Array of pin configurations related to the pinctrl config state
 */
struct pinctrl_state {
	unsigned int conf_count;
	struct pinconf *confs[];
};

struct pinctrl_ops {
	/* Apply a pinctrl configuration */
	TEE_Result (*conf_apply)(struct pinconf *conf);
	/* Release resources allocated for a pinctrl configuration */
	void (*conf_free)(struct pinconf *conf);
};

/**
 * pinctrl_dt_get_func - Typedef of function to get a pin configuration from
 * a device tree property
 *
 * @args: Pointer to device tree phandle arguments of the pin control reference
 * @data: Pointer to data given at pinctrl_register_provider() call
 * @out_pinconf: Output pin configuration reference upon success
 */
typedef TEE_Result (*pinctrl_dt_get_func)(struct dt_pargs *pargs, void *data,
					  struct pinconf **out_pinconf);

#ifdef CFG_DRIVERS_PINCTRL
/**
 * pinctrl_dt_register_provider - Register a pinctrl controller provider
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the pin controller
 * @get_pinctrl: Callback to match the pin controller with a struct pinconf
 * @data: Data which will be passed to the get_pinctrl callback
 * Return a TEE_Result compliant value
 */
static inline TEE_Result pinctrl_register_provider(const void *fdt,
						   int nodeoffset,
						   pinctrl_dt_get_func func,
						   void *data)
{
	return dt_driver_register_provider(fdt, nodeoffset,
					   (get_of_device_func)func, data,
					   DT_DRIVER_PINCTRL);
}

/**
 * pinctrl_get_state_by_name - Obtain a pinctrl state by name
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the pin controller
 * @name: name of the pinctrl state to obtain from device-tree
 * @state: Pointer filled with the retrieved state, must be freed after use
   using pinctrl_free_state()
 * Return a TEE_Result compliant value
 */
TEE_Result pinctrl_get_state_by_name(const void *fdt, int nodeoffset,
				     const char *name,
				     struct pinctrl_state **state);

/**
 * pinctrl_get_state_by_idx - Obtain a pinctrl state by index
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the pin controller
 * @pinctrl_id: Index of the pinctrl state to obtain from device-tree
 * @state: Pointer filled with the retrieved state, must be freed after use
   using pinctrl_free_state()
 * Return a TEE_Result compliant value
 */
TEE_Result pinctrl_get_state_by_idx(const void *fdt, int nodeoffset,
				    unsigned int pinctrl_id,
				    struct pinctrl_state **state);

/**
 * pinctrl_free_state - Free a pinctrl state that was previously obtained
 *
 * @state: State to be freed
 */
void pinctrl_free_state(struct pinctrl_state *state);

/**
 * pinctrl_apply_state - apply a pinctrl state
 *
 * @state: State to be applied
 * Return a TEE_Result compliant value
 */
TEE_Result pinctrl_apply_state(struct pinctrl_state *state);

/*
 * pinctrl_parse_dt_pin_modes - Parse DT node properties
 * @fdt: Device tree to work on
 * @nodeoffset: Pinctrl node
 * @modes: Output allocated regulator properties
 * Return a TEE_Result compliant value
 */
TEE_Result pinctrl_parse_dt_pin_modes(const void *fdt, int nodeoffset,
				      bitstr_t **modes);
#else /* CFG_DRIVERS_PINCTRL */
static inline TEE_Result
pinctrl_register_provider(const void *fdt __unused, int nodeoffset __unused,
			  get_of_device_func func __unused, void *data __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
pinctrl_get_state_by_name(const void *fdt __unused, int nodeoffset __unused,
			  const char *name __unused,
			  struct pinctrl_state **state __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result
pinctrl_get_state_by_idx(const void *fdt __unused, int nodeoffset __unused,
			 unsigned int pinctrl_id __unused,
			 struct pinctrl_state **state __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline void pinctrl_free_state(struct pinctrl_state *state __unused)
{
}

static inline TEE_Result pinctrl_apply_state(struct pinctrl_state *s __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result pinctrl_parse_dt_pin_modes(const void *fdt __unused,
						    int nodeoffset __unused,
						    bitstr_t **modes __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

#endif /* CFG_DRIVERS_PINCTRL */
#endif /* __DRIVERS_PINCTRL_H */
