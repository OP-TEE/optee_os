/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef _TA_QCOM_PAS_H
#define _TA_QCOM_PAS_H

#include <stdint.h>
#include <util.h>

/*
 * Interface to the TA which provides platform implementation of the
 * Peripheral Authentication service.
 */

#define TA_PAS_UUID { 0xcff7d191, 0x7ca0, 0x4784, \
		{ 0xaf, 0x13, 0x48, 0x22, 0x3b, 0x9a, 0x4f, 0xbe} }

/*
 * Peripheral Authentication Service (PAS) supported.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 */
#define TA_QCOM_PAS_IS_SUPPORTED		1

/*
 * PAS capabilities.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [out] params[1].value.a:	PAS capability flags
 */
#define TA_QCOM_PAS_CAPABILITIES		2

/*
 * PAS image initialization.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[1].memref:	Loadable firmware metadata
 */
#define TA_QCOM_PAS_INIT_IMAGE			3

/*
 * PAS memory setup.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[0].value.b:	Relocatable firmware size
 * [in]  params[1].value.a:	32bit LSB relocatable firmware memory address
 * [in]  params[1].value.b:	32bit MSB relocatable firmware memory address
 */
#define TA_QCOM_PAS_MEM_SETUP			4

/*
 * PAS get resource table.
 *
 * [in]     params[0].value.a:	Unique 32bit remote processor identifier
 * [in/out] params[1].memref:	Resource table config
 */
#define TA_QCOM_PAS_GET_RESOURCE_TABLE		5

/*
 * PAS image authentication and co-processor reset.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[0].value.b:	Firmware size
 * [in]  params[1].value.a:	32bit LSB firmware memory address
 * [in]  params[1].value.b:	32bit MSB firmware memory address
 * [in]  params[2].memref:	Optional fw memory space shared/lent
 */
#define TA_QCOM_PAS_AUTH_AND_RESET		6

/*
 * PAS co-processor set suspend/resume state.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[0].value.b:	Co-processor state identifier
 */
#define TA_QCOM_PAS_SET_REMOTE_STATE		7

/*
 * PAS co-processor shutdown.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 */
#define TA_QCOM_PAS_SHUTDOWN			8

#endif /* _TA_QCOM_PAS_H */
