/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#ifndef API_MONITOR_INDEX_H
#define API_MONITOR_INDEX_H

#define API_HAL_RET_VALUE_OK 0x00000000
#define API_HAL_RET_VALUE_SERVICE_UNKNWON 0xFFFFFFFF

/* Base for power management related services */
#define SECURE_SVC_PM       0x70

/* Carry out late actions as part of suspend sequence */
#define SECURE_SVC_PM_LATE_SUSPEND      (SECURE_SVC_PM + 1)

/* Base Index of APIs */
#define API_MONITOR_BASE_INDEX 0x00000100

/* Set the Debug control register */
#define API_MONITOR_L2CACHE_SETDEBUG_INDEX              (API_MONITOR_BASE_INDEX + 0x00000000)
/* Clean and invalidate physical address range */
#define API_MONITOR_L2CACHE_CLEANINVBYPA_INDEX          (API_MONITOR_BASE_INDEX + 0x00000001)
/* Enables/Disables the PL310 Cache */
#define API_MONITOR_L2CACHE_SETCONTROL_INDEX            (API_MONITOR_BASE_INDEX + 0x00000002)
/* Set the Auxiliary Control Register */
#define API_MONITOR_L2CACHE_SETAUXILIARYCONTROL_INDEX   (API_MONITOR_BASE_INDEX + 0x00000009)
/* Set the Data and Tag RAM Latency */
#define API_MONITOR_L2CACHE_SETLATENCY_INDEX            (API_MONITOR_BASE_INDEX + 0x00000012)
/* Set the Pre-fetch Control Register */
#define API_MONITOR_L2CACHE_SETPREFETCHCONTROL_INDEX    (API_MONITOR_BASE_INDEX + 0x00000013)

#endif /* API_MONITOR_INDEX_H */
