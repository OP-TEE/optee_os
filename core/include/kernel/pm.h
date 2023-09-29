/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __KERNEL_PM_H
#define __KERNEL_PM_H

#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * Platform hints on targeted power state. Hints are stored in a 32bit
 * unsigned value. Lower bits defines generic resource bit flags. Higher
 * bits stores a platform specific value specific platform driver may
 * understand. Registered callbacks may choose to use or ignore these hints.
 *
 * PM_HINT_CLOCK_STATE - When set clock shall be suspended/restored
 * PM_HINT_POWER_STATE - When set device power shall be suspended/restored
 * PM_HINT_IO_STATE - When set IO pins shall be suspended/restored
 * PM_HINT_CONTEXT_STATE - When set the full context be suspended/restored
 * PM_HINT_PLATFORM_STATE_MASK - Bit mask reserved for platform specific hints
 * PM_HINT_PLATFORM_STATE_SHIFT - LSBit position of platform specific hints mask
 */
#define PM_HINT_CLOCK_STATE		BIT(0)
#define PM_HINT_POWER_STATE		BIT(1)
#define PM_HINT_IO_STATE		BIT(2)
#define PM_HINT_CONTEXT_STATE		BIT(3)
#define PM_HINT_PLATFORM_STATE_MASK	GENMASK_32(31, 16)
#define PM_HINT_PLATFORM_STATE_SHIFT	U(16)

#define PM_HINT_STATE(_x)		((_x) & ~PM_HINT_PLATFORM_STATE_MASK)
#define PM_HINT_PLATFORM_STATE(_x) \
	(((_x) & PM_HINT_PLATFORM_STATE_MASK) >> PM_HINT_PLATFORM_STATE_SHIFT)

#define PM_HINT_IS_STATE(_x, _name) ((_x) & PM_HINT_ ## _name ## _STATE)

/*
 * PM_OP_SUSPEND: platform is suspending to a target low power state
 * PM_OP_RESUME: platform is resuming from low power state
 */
enum pm_op {
	PM_OP_SUSPEND = 0,
	PM_OP_RESUME = 1,
};

/*
 * Registered callbacks are called the ordering directives specified
 * by the PM_CB_ORDER_* value. Driver ordered callbacks at suspended
 * first/resumed last. Core service ordered callbacks are suspended
 * last/resumed first.
 */
enum pm_callback_order {
	PM_CB_ORDER_DRIVER = 0,
	PM_CB_ORDER_CORE_SERVICE,
	PM_CB_ORDER_MAX
};

#define PM_CALLBACK_HANDLE_INITIALIZER(_callback, _handle, _order, _name)\
		((struct pm_callback_handle){				\
			.callback = (_callback),			\
			.handle = (_handle),				\
			.order = (_order),				\
			.name = (_name),				\
		})

#define PM_CALLBACK_GET_HANDLE(pm_handle)	((pm_handle)->handle)

struct pm_callback_handle;
typedef TEE_Result (*pm_callback)(enum pm_op op, uint32_t pm_hint,
				  const struct pm_callback_handle *pm_handle);

/*
 * Drivers and services can register a callback function for the platform
 * suspend and resume sequences. A private address handle can be registered
 * with the callback and retrieved from the callback. Callback can be
 * registered with a specific call order as defined per PM_CB_ORDER_*.
 *
 * Callback shall return an error if failing to complete target transition.
 * This information may be used by the platform to resume a platform on
 * non-fatal failure to suspend.
 *
 * Callback implementations should ensure their functions belong to unpaged
 * memory sections (see DECLARE_KEEP_PAGER()) since the callback is likely to
 * be called from an unpaged execution context.
 *
 * Power Mamagement callback functions API:
 *
 * TEE_Result (*callback)(enum pm_op op,
 *			  unsigned int pm_hint,
 *			  const struct pm_callback_handle *pm_handle);
 *
 * @op - Target operation: either PM_SUSPEND or PM_RESUME
 * @pm_hint - Hints on power state platform suspends to /resumes from.
 *		PM_STATE_HINT_* defines the supported values.
 * @pm_handle - Reference to the struct pm_callback_handle related to to
 *		registered callback. Callback can retrieve the registered
 *		private handle with PM_CALLBACK_GET_HANDLE().
 *
 * Return a TEE_Result compliant return code
 */
/*
 * struct pm_callback_handle store the callback registration directives.
 *
 * @callback - Registered callback function
 * @handle - Registered private handler for the callback
 * @order - Registered callback call order priority (PM_CB_ORDER_*)
 * @flags - Flags set by pm core to keep track of execution
 * @name - Registered callback name
 */
struct pm_callback_handle {
	/* Set by the caller when registering a callback */
	pm_callback callback;
	void *handle;
	uint8_t order;
	/* Set by the system according to execution context */
	uint8_t flags;
	const char *name;
};

/*
 * Register a callback for suspend/resume sequence
 * Refer to struct pm_callback_handle for description of the callbacks
 * API and the registration directives.
 *
 * @pm_handle: Reference callback registration directives
 */
void register_pm_cb(struct pm_callback_handle *pm_handle);

/*
 * Register a driver callback for generic suspend/resume.
 * Refer to struct pm_callback_handle for description of the callbacks
 * API.
 *
 * @callback: Registered callback function
 * @handle: Registered private handle argument for the callback
 * @name: Registered callback name
 */
static inline void register_pm_driver_cb(pm_callback callback, void *handle,
					 const char *name)
{
	register_pm_cb(&PM_CALLBACK_HANDLE_INITIALIZER(callback, handle,
						       PM_CB_ORDER_DRIVER,
						       name));
}

/*
 * Register a core service callback for generic suspend/resume.
 * Refer to struct pm_callback_handle for description of the callbacks
 * API.
 *
 * @callback: Registered callback function
 * @handle: Registered private handle argument for the callback
 * @name: Registered callback name
 */
static inline void register_pm_core_service_cb(pm_callback callback,
					       void *handle, const char *name)
{
	register_pm_cb(&PM_CALLBACK_HANDLE_INITIALIZER(callback, handle,
						PM_CB_ORDER_CORE_SERVICE,
						name));
}

/*
 * Request call to registered PM callbacks
 *
 * @op: Either PM_OP_SUSPEND or PM_OP_RESUME
 * @pm_hint: Hint (PM_HINT_*) on state the platform suspends to/resumes from.
 *
 * Return a TEE_Result compliant status
 */
TEE_Result pm_change_state(enum pm_op op, uint32_t pm_hint);

#endif /*__KERNEL_PM_H*/
