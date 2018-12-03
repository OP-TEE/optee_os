// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    drv_mgt.c
 *
 * @brief   Global management of drivers registered with DRIVER_EXPORT
 *          macro and using the struct driver format (driver data and
 *          operations)
 */

/* Global includes */
#include <drivers/driver.h>
#include <initcall.h>
#include <kernel/spinlock.h>
#include <trace.h>

#ifdef DRV_MGT_DEBUG
#define MGTDRV_TRACE		DMSG
#else
#define MGTDRV_TRACE(...)
#endif

/**
 * @brief spinlock object to operate on the driver list
 */
unsigned int drv_spinlock = SPINLOCK_UNLOCK;

/**
 * @brief   Driver reference object building a chained
 *          list of drivers
 */
struct drv_ref {
	const struct driver  *drv;  ///< Register Driver structure
	enum drv_pwrmode     mode;  ///< Driver power mode
	void                 *data; ///< Driver's data if any

	SLIST_ENTRY(drv_ref) next;  ///< Link to the next driver in the list
};

static SLIST_HEAD(, drv_ref) drv_list = SLIST_HEAD_INITIALIZER(drv_ref);

/**
 * @brief   Allocation of the driver's data. This function is a weak
 *          function that can be overwritten in the platform
 *          implementation
 *
 * @param[in]  size   Data size to allocate
 *
 * @retval  address of the data buffer allocated
 * @retval  NULL if allocation error
 */
void __weak *drivers_alloc_data(size_t size)
{
#ifdef DRV_MGT_DEBUG
	MGTDRV_TRACE("Allocate %d bytes for driver", size);
#endif
	return malloc(size);
}

/**
 * @brief   Save the drivers data to enter in a power \a mode.
 *
 * @param[in]  mode   Power mode to enter
 * @param[in]  drv    Driver object
 * @param[in]  data   Driver's data
 *
 * @retval  TEE_SUCCESS        Success
 * @retval  TEE_ERROR_GENERIC  Generic error
 */
TEE_Result __weak drivers_save_data(enum drv_pwrmode mode __maybe_unused,
		const struct driver *drv __maybe_unused,
		void *data __maybe_unused)
{
#ifdef DRV_MGT_DEBUG
	MGTDRV_TRACE(
	"Driver [%s] save data @0x%"PRIxPTR" (%d bytes) to enter mode %d",
	drv->name, (uintptr_t)data, drv->data_size, mode);
#endif
	return TEE_SUCCESS;
}

/**
 * @brief   Restore the drivers data after resuning from power \a mode.
 *
 * @param[in]  mode   Power mode to enter
 * @param[in]  drv    Driver object
 * @param[in]  data   Driver's data
 *
 * @retval  TEE_SUCCESS        Success
 * @retval  TEE_ERROR_GENERIC  Generic error
 */
TEE_Result __weak drivers_restore_data(enum drv_pwrmode mode __maybe_unused,
		const struct driver *drv __maybe_unused,
		void *data __maybe_unused)
{
#ifdef DRV_MGT_DEBUG
	MGTDRV_TRACE(
	"Driver [%s] restore data @0x%"PRIxPTR" (%d bytes) after mode %d",
	drv->name, (uintptr_t)data, drv->data_size, mode);
#endif
	return TEE_SUCCESS;
}

/**
 * @brief   Installation of all registered drivers.\n
 *          Add all drivers in the drivers list in order
 *          to maintain drivers function of system power.
 *
 * @retval TEE_SUCCESS               Success
 * @retval TEE_ERROR_OUT_OF_MEMORY   Out of memory
 */
static TEE_Result do_install(void)
{
	struct drv_ref *new_elem;
	const struct driver *drv = NULL;

	const struct driver *start = SCATTERED_ARRAY_BEGIN(
						drivers, struct driver);
	const struct driver *end = SCATTERED_ARRAY_END(
						drivers, struct driver);

	for (drv = start; drv < end; drv++) {
		if (drv->ops) {
			if (!drv->ops->init) {
				MGTDRV_TRACE(
				"Driver [%s] not install no Init function",
				drv->name);
				continue;
			}

			MGTDRV_TRACE("Add driver [%s] in the list", drv->name);

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
			new_elem->data = NULL;
			new_elem->mode = OFF;

			if (drv->data_size) {
				new_elem->data = drivers_alloc_data(
							drv->data_size);
				if (!new_elem->data)
					return TEE_ERROR_OUT_OF_MEMORY;
			}

			SLIST_INSERT_HEAD(&drv_list, new_elem, next);
		}
#ifdef DRV_MGT_DEBUG
		else
			MGTDRV_TRACE("Driver [%s] OPS not defined", drv->name);
#endif

	}

	IMSG("Drivers installation success");

	return TEE_SUCCESS;
}

/**
 * @brief   Initialization of all driver in the list.\n
 *
 * @note    Return TEE_SUCCESS in case there is no driver
 *
 * @retval TEE_SUCCESS       Success
 * @retval TEE_ERROR_GENERIC Generic error
 */
static TEE_Result do_init(void)
{
	TEE_Result ret;
	uint8_t error_counter = 0;

	struct drv_ref *drv_elem;

	SLIST_FOREACH(drv_elem, &drv_list, next) {
		ret = drv_elem->drv->ops->init(drv_elem->data);
		MGTDRV_TRACE("Driver [%s] init ret 0x%"PRIx32"",
				drv_elem->drv->name, ret);
		if (ret == TEE_SUCCESS)
			drv_elem->mode = ON;
		else {
			SLIST_REMOVE(&drv_list, drv_elem, drv_ref, next);
			free(drv_elem);
			error_counter++;
		}
	}

	return (error_counter) ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}

/**
 * @brief   Prepare all drivers to enter in a the given power \a mode.
 *          Function of the \a wait parameter:
 *           - \a wait = TRUE, the driver must complete the power mode
 *           entry procedure before returning.
 *           - \a wait = FALSE, the driver checks if it's ready or not.
 *           If not, it return TEE_ERROR_BUSY, otherwise it switches in
 *           the requested power mode.
 *
 * @note    Return TEE_SUCCESS in case there is no driver
 *
 * @param[in]  mode   Power mode to switch to
 * @param[in]  wait   TRUE to wait until power mode reach
 *
 * @retval TEE_SUCCESS       Success
 * @retval TEE_ERROR_BUSY    At least one driver can not be switched
 * @retval TEE_ERROR_GENERIC Generic error
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

			ret = drv_elem->drv->ops->pm_enter(drv_elem->data,
					mode, wait);
			MGTDRV_TRACE("Driver [%s] switch to %d ret 0x%"PRIx32"",
					drv_elem->drv->name, mode, ret);

			switch (ret) {
			case TEE_SUCCESS:
				if (drv_elem->data) {
					ret = drivers_save_data(mode,
							drv_elem->drv,
							drv_elem->data);
					if (ret != TEE_SUCCESS)
						goto exit_pm_enter;
				}

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

/**
 * @brief   Resume all drivers for their power mode.\n
 *          Do check error, driver must react itself in case
 *          of resume error.
 */
void drivers_pm_resume(void)
{
	TEE_Result ret;

	struct drv_ref *drv_elem;

	cpu_spin_lock(&drv_spinlock);

	SLIST_FOREACH(drv_elem, &drv_list, next) {
		if (drv_elem->drv->ops->pm_resume) {
			/* If state is ON, don't resume */
			if (drv_elem->mode == ON)
				continue;

			if (drv_elem->data) {
				ret = drivers_restore_data(drv_elem->mode,
						drv_elem->drv, drv_elem->data);
				if (ret != TEE_SUCCESS)
					continue;
			}

			drv_elem->drv->ops->pm_resume(drv_elem->data,
				drv_elem->mode);
			MGTDRV_TRACE("Driver [%s] resume",
					drv_elem->drv->name);

			drv_elem->mode = ON;
		}
	}

	cpu_spin_unlock(&drv_spinlock);
}

/**
 * @brief   Initialization of all registered driver.\n
 *          Build a list of drivers and if success
 *          call all drivers of the list.
 *
 * @retval TEE_SUCCESS             Success
 * @retval TEE_ERROR_OUT_OF_MEMORY Out of memory
 * @retval TEE_ERROR_GENERIC       Generic error
 */
static TEE_Result drivers_init(void)
{
	TEE_Result ret;

	ret = do_install();

	if (ret == TEE_SUCCESS)
		ret = do_init();

	return ret;
}

driver_init(drivers_init);
