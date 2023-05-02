/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew Davis <afd@ti.com>
 */

#ifndef API_MONITOR_INDEX_H
#define API_MONITOR_INDEX_H

#define API_HAL_RET_VALUE_OK 0x00000000
#define API_HAL_RET_VALUE_SERVICE_UNKNWON 0xFFFFFFFF

/* Base Index of APIs */
#define API_MONITOR_BASE_INDEX 0x00000100

/* HyperVisor Start */
#define API_MONITOR_HYP_STARTHYPERVISOR_INDEX   (API_MONITOR_BASE_INDEX + 0x00000002)
/* Caches cleaning */
#define API_MONITOR_CACHES_CLEAN_INDEX          (API_MONITOR_BASE_INDEX + 0x00000003)
/* Write the L2 Cache Controller Auxiliary Control */
#define API_MONITOR_L2ACTLR_SETREGISTER_INDEX   (API_MONITOR_BASE_INDEX + 0x00000004)
/* Set the Data and Tag RAM Latency */
#define API_MONITOR_L2CACHE_SETLATENCY_INDEX    (API_MONITOR_BASE_INDEX + 0x00000005)
/* L2 Cache Prefetch Control Register */
#define API_MONITOR_L2PFR_SETREGISTER_INDEX     (API_MONITOR_BASE_INDEX + 0x00000006)
/* Set Auxiliary Control Register */
#define API_MONITOR_ACTLR_SETREGISTER_INDEX     (API_MONITOR_BASE_INDEX + 0x00000007)
/* AMBA IF mode */
#define API_MONITOR_WUGEN_MPU_SETAMBAIF_INDEX   (API_MONITOR_BASE_INDEX + 0x00000008)
/* Timer CNTFRQ register set */
#define API_MONITOR_TIMER_SETCNTFRQ_INDEX       (API_MONITOR_BASE_INDEX + 0x00000009)

#endif /* API_MONITOR_INDEX_H */
