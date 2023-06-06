/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 */

#ifndef __DRIVERS_RSTCTRL_H
#define __DRIVERS_RSTCTRL_H

#include <kernel/dt_driver.h>
#include <stdint.h>
#include <tee_api_types.h>

struct rstctrl;

struct rstctrl_ops {
	/*
	 * Operators on reset control(s) exposed by a reset controller
	 *
	 * @assert_level: Assert reset level on control with a timeout hint
	 * @deassert_level: Deassert reset level on control with a timeout hint
	 * @get_name: Get a string name for the controller, or NULL is none
	 *
	 * Operator functions @assert_level and @deassert_level use arguments:
	 * @rstctrl: Reset controller
	 * @id: Identifier for the reset level control in the reset controller
	 * @to_ms: Timeout in microseconds or RSTCTRL_NO_TIMEOUT, may be ignored
	 * by reset controller.
	 * Return a TEE_Result compliant code.
	 */
	TEE_Result (*assert_level)(struct rstctrl *rstctrl, unsigned int to_us);
	TEE_Result (*deassert_level)(struct rstctrl *rstctrl,
				     unsigned int to_us);
	const char *(*get_name)(struct rstctrl *rstctrl);
};

/*
 * struct rstctrl - Instance of a control exposed by a reset controller
 * @ops: Operators of the reset controller
 * @exclusive: Set when a consumer has exclusive control on the reset level
 */
struct rstctrl {
	const struct rstctrl_ops *ops;
	bool exclusive;
};

/**
 * RSTCTRL_DECLARE - Declare a reset controller driver with a single
 * device tree compatible string.
 *
 * @__name: Reset controller driver name
 * @__compat: Compatible string
 * @__probe: Reset controller probe function
 */
#define RSTCTRL_DT_DECLARE(__name, __compat, __probe) \
	static const struct dt_device_match __name ## _match_table[] = { \
		{ .compatible = __compat }, \
		{ } \
	}; \
	DEFINE_DT_DRIVER(__name ## _dt_driver) = { \
		.name = # __name, \
		.type = DT_DRIVER_RSTCTRL, \
		.match_table = __name ## _match_table, \
		.probe = __probe, \
	}

/*
 * Platform driver may ignore the timeout hint according to their
 * capabilities. RSTCTRL_NO_TIMEOUT specifies no timeout hint.
 */
#define RSTCTRL_NO_TIMEOUT	0

/*
 * rstctrl_assert_to - Assert reset control possibly with timeout
 * rstctrl_assert - Assert reset control
 * rstctrl_deassert_to - Deassert reset control possibly with timeout
 * rstctrl_deassert - Deassert reset control
 *
 * @rstctrl: Reset controller
 * @to_us: Timeout in microseconds
 * Return a TEE_Result compliant code
 */
static inline TEE_Result rstctrl_assert_to(struct rstctrl *rstctrl,
					   unsigned int to_us)
{
	return rstctrl->ops->assert_level(rstctrl, to_us);
}

static inline TEE_Result rstctrl_assert(struct rstctrl *rstctrl)
{
	return rstctrl_assert_to(rstctrl, RSTCTRL_NO_TIMEOUT);
}

static inline TEE_Result rstctrl_deassert_to(struct rstctrl *rstctrl,
					     unsigned int to_us)
{
	return rstctrl->ops->deassert_level(rstctrl, to_us);
}

static inline TEE_Result rstctrl_deassert(struct rstctrl *rstctrl)
{
	return rstctrl_deassert_to(rstctrl, RSTCTRL_NO_TIMEOUT);
}

/*
 * rstctrl_name - Get a name for the reset level control or NULL
 *
 * @rstctrl: Reset controller
 * Return a pointer to controller name or NULL
 */
static inline const char *rstctrl_name(struct rstctrl *rstctrl)
{
	if (rstctrl->ops->get_name)
		return rstctrl->ops->get_name(rstctrl);

	return NULL;
}

/**
 * rstctrl_dt_get_exclusive - Get exclusive access to reset controller
 *
 * @rstctrl: Reset controller
 * Return a TEE_Result compliant value
 */
TEE_Result rstctrl_get_exclusive(struct rstctrl *rstctrl);

/**
 * rstctrl_put_exclusive - Release exclusive access to target
 *
 * @rstctrl: Reset controller
 */
void rstctrl_put_exclusive(struct rstctrl *rstctrl);

/**
 * rstctrl_ops_is_valid - Check reset controller ops is valid
 *
 * @ops: Reference to reset controller operator instance
 */
static inline bool rstctrl_ops_is_valid(const struct rstctrl_ops *ops)
{
	return ops && ops->assert_level && ops->deassert_level;
}

#ifdef CFG_DT
/**
 * rstctrl_dt_get_by_index - Get a reset controller at a specific index in
 * 'resets' property
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the subnode containing a 'resets' property
 * @index: Reset controller index in 'resets' property
 * @rstctrl: Output reset controller reference upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if reset controller is not initialized
 * Return TEE_ERROR_ITEM_NOT_FOUND if the resets property does not exist
 * Return a TEE_Result compliant code in case of error
 */
static inline TEE_Result rstctrl_dt_get_by_index(const void *fdt,
						 int nodeoffset,
						 unsigned int index,
						 struct rstctrl **out_rstctrl)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void *rstctrl = NULL;

	res = dt_driver_device_from_node_idx_prop("resets", fdt, nodeoffset,
						  index, DT_DRIVER_RSTCTRL,
						  &rstctrl);
	if (!res)
		*out_rstctrl = rstctrl;

	return res;
}
#else
static inline TEE_Result rstctrl_dt_get_by_index(const void *fdt __unused,
						 int nodeoffset __unused,
						 unsigned int index __unused,
						 struct rstctrl **ctrl __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /*CFG_DT*/

/**
 * rstctrl_dt_get_by_name - Get a reset controller matching a name in the
 * 'reset-names' property
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the subnode containing a 'resets' property
 * @name: Reset controller name to get
 * @rstctrl: Output reset controller reference upon success
 *
 * Return TEE_SUCCESS in case of success
 * Return TEE_ERROR_DEFER_DRIVER_INIT if reset controller is not initialized
 * Return TEE_ERROR_ITEM_NOT_FOUND if the reset-names property does not exist
 * Return a TEE_Result compliant code in case of error
 */
TEE_Result rstctrl_dt_get_by_name(const void *fdt, int nodeoffset,
				  const char *name, struct rstctrl **rstctrl);

/**
 * rstctrl_dt_get_func - Typedef of function to get reset controller from
 * devicetree properties
 *
 * @args: Pointer to devicetree description of the reset controller to parse
 * @data: Pointer to data given at rstctrl_dt_register_provider() call
 * @rstctrl: Output reset controller reference upon success
 */
typedef TEE_Result (*rstctrl_dt_get_func)(struct dt_pargs *args, void *data,
					  struct rstctrl **out_rstctrl);

/**
 * rstctrl_dt_register_provider - Register a reset controller provider
 *
 * @fdt: Device tree to work on
 * @nodeoffset: Node offset of the reset controller
 * @func: Callback to match the reset controller with a struct rstctrl
 * @data: Data which will be passed to the get_dt_rstctrl callback
 * Returns TEE_Result value
 */
static inline TEE_Result rstctrl_register_provider(const void *fdt,
						   int nodeoffset,
						   rstctrl_dt_get_func func,
						   void *data)
{
	return dt_driver_register_provider(fdt, nodeoffset,
					   (get_of_device_func)func, data,
					   DT_DRIVER_RSTCTRL);
}
#endif /* __DRIVERS_RSTCTRL_H */

