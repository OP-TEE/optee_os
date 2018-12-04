/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018 NXP
 *
 * File    driver.h
 *
 * Brief   Definition of the generic driver object opened, closed,
 *         suspended and resumed by the system.
 *
 */
#ifndef __DRIVER_H__
#define __DRIVER_H__

#include <scattered_array.h>
#include <tee_api_types.h>
#include <util.h>

#ifndef CFG_PLAT_PWR
/*
 * Default Enumerate the driver power mode state.
 *
 * But it's still possible to redefine the `enum drv_pwrmode` to be
 * platform specific.
 * For that the include file `platform_pw.h` has to be present in
 * which the `enum drv_pwrmode` is redefined. Then the platform must
 * be built with the `CFG_PLAT_PWR` compilation flag.
 *
 * Note: The STATE_UNKNOWN and STATE_RUNNING state must be defined
 *       even if redefined in the platform specific enumerate.
 */
enum drv_pwrmode {
	STATE_UNKNOWN = 0,   // Unknown Power state
	STATE_RUNNING,       // Power up and running
	STATE_SUSPEND        // System suspend mode
};
#else
#include <platform_pwr.h>
#endif

/*
 * Driver object operations. Some can be optional.
 */
struct driver_ops {
	// Driver initialization
	TEE_Result (*init)(void);
	// Request driver power state entry
	TEE_Result (*pm_enter)(enum drv_pwrmode mode, bool wait);
	// Resume driver to be running mode
	void (*pm_resume)(enum drv_pwrmode mode);
};

/*
 * Driver object referencing driver operations.
 */
struct driver {
	const char              *name;     // Name of the driver
	const struct driver_ops *ops;      // Driver's operation functions
};

#define __define_drivers(...) \
	SCATTERED_ARRAY_DEFINE_PG_ITEM(drivers, struct driver) = \
		{ __VA_ARGS__ }


/*
 * Register driver with debug information
 */
#define REGISTER_DRIVER(_name, _ops) \
	__define_drivers(.name = TO_STR(_name), .ops = _ops)

TEE_Result drivers_pm_enter(enum drv_pwrmode mode, bool wait);
void drivers_pm_resume(void);

#endif /* __DRIVER_H__ */
