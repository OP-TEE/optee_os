/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Texas Instruments
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES// LOSS OF USE, DATA, OR PROFITS// OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
