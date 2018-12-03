# OP-TEE Generic Driver Object

## Contents
1. [Introduction](#1-introduction)
2. [Implementation details](#2-implementation-details)
   * [Object driver structure](#21-object-driver-structure)
   * [Driver registration](#22-driver-registration)
   * [Driver data](#23-driver-data)
   * [Driver operations](#24driver-operations)

## 1. Introduction
A concept of driver object is introduced in OP-TEE through the generic `struct driver` available in the `core/include/drivers/driver.h` include file.

This generic object has been designed to allow power management at driver level, hence to prepare the driver to enter in power transition. This mechanism is useful for driver:
   * using DMA (Direct Memory Access) transfers to a memory that will be shutdown
   * losing configuration because clocks and/or power domain are shutdown

## 2. Implementation details
### 2.1 Object driver structure

```
struct driver {
#ifdef DRV_MGT_DEBUG
	const char              *name;
#endif
	const size_t            data_size;
	const struct driver_ops *ops;
};
```

The *driver* structure is composed of 3 fields:
   * *name*: debug purpose only, specify the name of the driver.
   * *data_size*: size in bytes of the driver's data given to all driver's operations. Value can be 0, if no data needed, otherwise data object is allocated by the `drivers_alloc_data` function. Refer to [driver data](#23-driver-data)
   * *ops*: [driver's operations](#24-driver's-operations) reference

### 2.2 Driver registration

A new driver object is registered in the system through the `REGISTER_DRIVER` macro:

`#define REGISTER_DRIVER(_name, _data_size, _ops)`

The macro has 3 parameters:
   * *_name*: name of the driver. This value is also used for debug purpose (field *name* of *struct driver*.
   * *_data_size*: size in bytes of the driver's data.
   * *_ops*: driver operations object.

### 2.3 Driver data
Driver's data can be allocated if the driver object field *data_size* is not 0. These data is by default allocated in OP-TEE Heap with the weak function `drivers_alloc_data`. This function can be re-implemented on platform basis to allocate data in another place (e.g. in Secure device internal RAM).

One of the objective is to ensure that driver's data are saved (encrypted or not) before memory is lost during a low power mode. Data are saved and restored by the weak functions `drivers_save_data` and `drivers_restore_data`. Default functions do nothing.

### 2.4 Driver operations

```
struct driver_ops {
	TEE_Result (*init)     (void *drvdata);
	TEE_Result (*pm_enter) (void *drvdata, enum drv_pwrmode mode, bool wait);
	void       (*pm_resume)(void *drvdata, enum drv_pwrmode mode);
};
```

The *driver_ops* structure propose 3 functions:
   * *init*: this function is the only mandatory function to install the driver in the system. This function is called first during OP-TEE initialization stage. If the function is not defined or returns an error, the driver is removed from the list of system driver.
   * *pm_enter*: this function is called to inform driver that system is going to enter in a power mode.
   * *pm_resume*: this function is called to inform driver that system exited the power mode.

Default Power modes are:

```
enum drv_pwrmode {
	ON = 0,
	IDLE,
	OFF
};
```

| Mode      | Description           |
|:---------:|:----------------------|
| **ON**    | Power up and running  |
| **IDLE**  | Low Power mode idle   |
| **OFF**   | Power OFF             |

But it's still possible to redefine the `enum drv_pwrmode` to be platform specific.
For that the include file *platform_pw.h* has to be present in which the `enum drv_pwrmode` is redefined. Then the platform must be built with the `CFG_PLAT_PWR` compilation flag.

## 3 Power management
Power management is device dependent. It's explained in the section 7 [Power Management](./porting_guidelines.md#7-power-management--psci) of the [Porting guidelines for OP-TEE](./porting_guidelines.md).

### 3.1 Generic driver API
In the same logic, the driver's power mode control should be called by the system power management function.
For that two generic driver API are available:
1. `drivers_pm_enter`

If defined, this function calls each drivers *pm_enter* function. All driver's *pm_enter* are called while there is no error reported by a driver (*pm_enter* return *TEE_SUCCESS*) and only if the driver in not already in the expected mode. In case of driver's *pm_enter* success, the function `drivers_save_data` is executed to eventually save driver's data if any.

``` TEE_Result drivers_pm_enter(enum drv_pwrmode mode, bool wait) ```

| Parameter | Description |
|:----------|:------------|
| *mode*    | The power mode to reach |
| *wait*    | if **true**, the driver should not return while not ready to enter in the power mode. |
|           | if **false**, driver *pm_enter* function can return with TEE_ERROR_BUSY code indicating it's not ready.|

| Return              | Description |
|:--------------------|:------------|
| *TEE_SUCCESS*       | All drivers are ready to enter in the power mode |
| *TEE_ERROR_BUSY*    | At least one of the driver is not ready |
| *TEE_ERROR_GENERIC* | An error occurred during the procedure |

2. `drivers_resume`

If defined, this function calls each drivers *pm_resume* function. Before calling the driver's *pm_resume* function, the driver's data (if any) are restored by calling the `drivers_restore_data` function. If data restoration failed, the driver is not resumed from power mode.:wait

``` void drivers_pm_resume(void) ```

### 3.2 Driver data save/restore
The generic driver object offers the possibility to backup driver's data before entering a system power mode. On certain platform, it could be useful when system off mode is entered because volatile memory can be powered off.
For that 2 weak function are proposed:

`TEE_Result drivers_save_data(enum drv_pwrmode mode, const struct driver *drv, void *data);`

The function is executed after driver successfully enter a power mode (after *pm_enter*).

| Parameter | Description |
|:----------|:------------|
| *mode*    | The power mode to reach |
| *drv*     | Reference to the driver object |
| *data*    | Data buffer address to save |


| Return              | Description |
|:--------------------|:------------|
| *TEE_SUCCESS*       | Data save success |
| *TEE_ERROR_GENERIC* | An error occurred during the procedure |


`TEE_Result drivers_restore_data(enum drv_pwrmode mode, const struct driver *drv, void *data);`

The function is executed before resuming driver from a power mode (before *pm_resume*). If data restoration failed, the driver is not resumed but drivers power mode continue to resume the next driver in the system list.

| Parameter | Description |
|:----------|:------------|
| *mode*    | The power mode to reach |
| *drv*     | Reference to the driver object |
| *data*    | Data buffer address where to restore |


| Return              | Description |
|:--------------------|:------------|
| *TEE_SUCCESS*       | Data restore success |
| *TEE_ERROR_GENERIC* | An error occurred during the procedure |

