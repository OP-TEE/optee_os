/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __SMCCC_H
#define __SMCCC_H

/*
 * Describes features of SMC Calling Convention from v1.1
 * See also https://developer.arm.com/-/media/developer/pdf/ARM_DEN_0070A_Firmware_interfaces_for_mitigating_CVE-2017-5715.pdf
 */

/*
 * Retrieve the implemented version of the SMC Calling Convention
 * Mandatory from SMCCC v1.1
 * Optional in SMCCC v1.0
 */
#define SMCCC_VERSION		0x80000000

/*
 * Determine the availability and capability of Arm Architecture Service
 * functions.
 * Mandatory from SMCCC v1.1
 * Optional for SMCCC v1.0
 */
#define SMCCC_ARCH_FEATURES	0x80000001

/*
 * Execute the mitigation for CVE-2017-5715 on the calling PE
 * Optional from SMCCC v1.1
 * Not supported in SMCCC v1.0
 */
#define SMCCC_ARCH_WORKAROUND_1	0x80008000

#endif /*__SMCCC_H*/
