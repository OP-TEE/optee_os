// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018 NXP
 *
 * File    drv_mgt.c
 *
 * Brief   Global management of drivers registered with REGISTER_DRIVER
 *         macro and using the struct driver format (driver data and
 *         operations).
 *
 * The concept of driver object is introduced in OP-TEE through the
 * `struct driver` available in the `core/include/drivers/driver.h`
 * include file.
 *
 * This object has been designed to allow power management at driver level,
 * hence to prepare the driver to enter in power transition.
 * This mechanism is useful for driver:
 *   - using DMA (Direct Memory Access) transfers to a memory that will
 *   be shutdown
 *   - losing configuration because clocks and/or power domain are shutdown
 *
 * Exported APIs to be called in the power management framework (e.g. PSCI)
 *
 *  - Switch in a power mode
 * TEE_Result drivers_pm_enter(enum drv_pwrmode mode, bool wait)
 *
 *  - Resume from power mode
 * void drivers_pm_resume(void)
 */

/* Global includes */
#include <drivers/driver.h>
#include <initcall.h>
#include <kernel/spinlock.h>
#include <trace.h>

/*
 * spinlock object to operate on the driver list
 */
unsigned int drv_spinlock = SPINLOCK_UNLOCK;

/*
 * Driver reference object building a chained
 * list of drivers
 */
struct drv_ref {
	const struct driver  *drv;  // Register Driver structure
	enum drv_pwrmode     mode;  // Driver power mode

	SLIST_ENTRY(drv_ref) next;  // Link to the next driver in the list
};

static SLIST_HEAD(, drv_ref) drv_list = SLIST_HEAD_INITIALIZER(drv_ref);

/*
 * brief   Installation of all registered drivers.
 *         Add all drivers in the drivers list in order
 *         to maintain drivers function of system power.
 *
 * return TEE_SUCCESS               Success
 *        TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_install(void)
{
	struct drv_ref *new_elem;
	struct drv_ref *elem;
	const struct driver *drv = NULL;

	SCATTERED_ARRAY_FOREACH(drv, drivers, struct driver) {
		if (drv->ops) {
			if (!drv->ops->init) {
				DMSG(
				"Driver [%s] not installed no Init function",
				drv->name);
				continue;
			}

			DMSG("Add driver [%s] in the list", drv->name);

			/*
			 * Allocate a new driver reference element to
			 * be added in the driver list
			 */
			new_elem = malloc(sizeof(struct drv_ref));
			if (!new_elem)
				return TEE_ERROR_OUT_OF_MEMORY;

			/*
			 * Fill and add the new driver reference into the
			 * list at the head of the list.
			 */
			new_elem->drv  = drv;
			new_elem->mode = STATE_UNKNOWN;

			elem = SLIST_FIRST(&drv_list);
			if (elem) {
				while (SLIST_NEXT(elem, next))
					elem = SLIST_NEXT(elem, next);

				SLIST_INSERT_AFTER(elem, new_elem, next);
			} else
				SLIST_INSERT_HEAD(&drv_list, new_elem, next);
		} else {
			DMSG("Driver [%s] OPS not defined", drv->name);
		}
	}

	IMSG("Drivers installation success");

	return TEE_SUCCESS;
}

/*
 * brief   Initialization of all driver in the list.\n
 *
 * note    Return TEE_SUCCESS in case there is no driver
 *
 * return TEE_SUCCESS       Success
 *        TEE_ERROR_GENERIC Generic error
 */
static TEE_Result do_init(void)
{
	TEE_Result ret;
	uint8_t error_counter = 0;

	struct drv_ref *drv_elem;

	SLIST_FOREACH(drv_elem, &drv_list, next) {
		ret = drv_elem->drv->ops->init();
		DMSG("Driver [%s] init ret 0x%"PRIx32"",
				drv_elem->drv->name, ret);
		if (ret == TEE_SUCCESS)
			drv_elem->mode = STATE_RUNNING;
		else {
			SLIST_REMOVE(&drv_list, drv_elem, drv_ref, next);
			free(drv_elem);
			error_counter++;
		}
	}

	return (error_counter) ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

/*
 * brief    Prepare all drivers to enter in a the given power mode.
 *          Function of the wait parameter:
 *           - wait = TRUE, the driver must complete the power mode
 *           entry procedure before returning.
 *           - wait = FALSE, the driver checks if it's ready or not.
 *           If not, it return TEE_ERROR_BUSY, otherwise it switches in
 *           the requested power mode.
 *
 * note    Return TEE_SUCCESS in case there is no driver
 *
 * inputs:  mode   Power mode to switch to
 *          wait   TRUE to wait until power mode reach
 *
 * return TEE_SUCCESS       Success
 *        TEE_ERROR_BUSY    At least one driver can not be switched
 *        TEE_ERROR_GENERIC Generic error
 */
TEE_Result drivers_pm_enter(enum drv_pwrmode mode, bool wait)
{
	TEE_Result ret;

	struct drv_ref *drv_elem;
	uint8_t busy_count = 0;

	cpu_spin_lock(&drv_spinlock);

	SLIST_FOREACH(drv_elem, &drv_list, next) {
		if (drv_elem->drv->ops->pm_enter) {
			/* If state is already in requested mode, go next */
			if (drv_elem->mode == mode)
				continue;

			ret = drv_elem->drv->ops->pm_enter(mode, wait);
			DMSG("Driver [%s] switch to %d ret 0x%"PRIx32"",
					drv_elem->drv->name, mode, ret);

			switch (ret) {
			case TEE_SUCCESS:
				drv_elem->mode = mode;
				break;

			case TEE_ERROR_BUSY:
				/*
				 * If wait mode is asked, there is a driver
				 * error hence return in error.
				 * Otherwise increment the busy counter and
				 * continue to switch next drivers
				 */
				if (wait) {
					ret = TEE_ERROR_GENERIC;
					goto exit_pm_enter;
				}

				busy_count++;
				break;

			default:
				/* Other error causing system instability */
				goto exit_pm_enter;
			}
		}
	}

	if (!wait)
		ret = (busy_count) ? TEE_ERROR_BUSY : TEE_SUCCESS;
	else
		ret = TEE_SUCCESS;

exit_pm_enter:
	cpu_spin_unlock(&drv_spinlock);
	return ret;
}

/*
 * brief    Resume all drivers from their power mode.
 *          Don't check error, driver must react itself in case
 *          of resume error.
 */
void drivers_pm_resume(void)
{
	struct drv_ref *drv_elem;

	cpu_spin_lock(&drv_spinlock);

	SLIST_FOREACH(drv_elem, &drv_list, next) {
		if (drv_elem->drv->ops->pm_resume) {
			/* If state is ON, don't resume */
			if (drv_elem->mode == STATE_RUNNING)
				continue;

			drv_elem->drv->ops->pm_resume(drv_elem->mode);
			DMSG("Driver [%s] resume", drv_elem->drv->name);

			drv_elem->mode = STATE_RUNNING;
		}
	}

	cpu_spin_unlock(&drv_spinlock);
}

/*
 * brief    Initialization of all registered driver.
 *          Build a list of drivers and if success
 *          call all drivers of the list.
 *
 * return TEE_SUCCESS             Success
 *        TEE_ERROR_OUT_OF_MEMORY Out of memory
 *        TEE_ERROR_GENERIC       Generic error
 */
static TEE_Result drivers_init(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = do_install();

	if (ret == TEE_SUCCESS)
		ret = do_init();

	return ret;
}

driver_init(drivers_init);
