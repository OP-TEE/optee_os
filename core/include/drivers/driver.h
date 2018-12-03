/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    driver.h
 *
 * @brief   Definition of the generic driver object opened, closed,
 *          suspended and resumed by the system.
 *
 */
#ifndef __DRIVER_H__
#define __DRIVER_H__

#include <scattered_array.h>
#include <tee_api_types.h>
#include <trace.h>

#if TRACE_LEVEL >= TRACE_DEBUG
#define DRV_MGT_DEBUG
#endif

#ifndef CFG_PLAT_PWR
/**
 * @brief   Enumerate the driver power mode state
 */
enum drv_pwrmode {
	ON = 0,   ///< Power up and running
	IDLE,     ///< Low Power mode Idle
	OFF       ///< Power OFF
};
#else
#include <platform_pwr.h>
#endif

/**
 * @brief   Generic driver object operations. Some can be optional.
 */
struct driver_ops {
	/// Driver initialization
	TEE_Result (*init)(void *drvdata);
	/// Switch driver in either Idle or OFF mode
	TEE_Result (*pm_enter)(void *drvdata, enum drv_pwrmode mode, bool wait);
	/// Resume driver from Idle or Power Off
	void (*pm_resume)(void *drvdata, enum drv_pwrmode mode);
};

/**
 * @brief   Generic driver object referencing driver data and operations.
 *          Driver's data can be optional (data_size = 0).
 *          Driver data is allocated by the generic installer
 *          to allow the control of the data's area. Data area can so
 *          be saved/restored in secure place in case of power mode
 *          when normal memory is lost. (e.g System OFF)
 */
struct driver {
#ifdef DRV_MGT_DEBUG
	const char              *name;     ///< Name of the driver (debug only)
#endif
	const size_t            data_size; ///< Driver's private data size
	const struct driver_ops *ops;      ///< Driver's operation functions
};

#define concat(a, b)	a ## b
#define STR(s)			#s

#define __define_drivers(...) \
	SCATTERED_ARRAY_DEFINE_PG_ITEM(drivers, struct driver) = \
		{ __VA_ARGS__ }

#ifdef DRV_MGT_DEBUG

/*
 * Register driver with debug information
 */
#define REGISTER_DRIVER(_name, _data_size, _ops) \
	__define_drivers(.name = STR(_name), \
			.data_size = _data_size, \
			.ops = _ops)
#else

/*
 * Register driver without debug information
 */
#define REGISTER_DRIVER(_name, _data_size, _ops) \
	__define_drivers(.data_size = _data_size, \
			.ops = _ops)

#endif

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
void *drivers_alloc_data(size_t size);

/**
 * @brief   Prepare all drivers to Idle or power off mode. Function
 *          of the \a wait parameter:
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
TEE_Result drivers_pm_enter(enum drv_pwrmode mode, bool wait);

/**
 * @brief   Resume all drivers for their power mode.\n
 *          Do check error, driver must react itself in case
 *          of resume error.
 */
void drivers_pm_resume(void);

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
TEE_Result drivers_save_data(enum drv_pwrmode mode,
		const struct driver *drv, void *data);

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
TEE_Result drivers_restore_data(enum drv_pwrmode mode,
		const struct driver *drv, void *data);

#endif /* __DRIVER_H__ */
