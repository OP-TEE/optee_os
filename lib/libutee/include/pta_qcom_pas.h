/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __PTA_QCOM_PAS_H
#define __PTA_QCOM_PAS_H

#include <stdint.h>
#include <util.h>

/*
 * Interface to the pseudo TA which provides platform implementation
 * of the remote processor management
 */

#define PTA_QCOM_PAS_UUID { 0xdaedbae4, 0xcf3e, 0x4b76, \
		{ 0xa5, 0xc5, 0xdb, 0xf8, 0xb6, 0xfd, 0x5a, 0xf4} }

/*
 * Peripheral Authentication Service (PAS) supported.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 */
#define PTA_QCOM_PAS_IS_SUPPORTED		1

/*
 * PAS capabilities.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [out] params[1].value.a:	PAS capability flags
 */
#define PTA_QCOM_PAS_CAPABILITIES		2

/*
 * PAS image initialization.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[1].memref:	Loadable firmware metadata
 */
#define PTA_QCOM_PAS_INIT_IMAGE			3

/*
 * PAS memory setup.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[0].value.b:	Relocatable firmware size
 * [in]  params[1].value.a:	32bit LSB relocatable firmware memory address
 * [in]  params[1].value.b:	32bit MSB relocatable firmware memory address
 */
#define PTA_QCOM_PAS_MEM_SETUP			4

/*
 * PAS get resource table.
 *
 * [in]     params[0].value.a:	Unique 32bit remote processor identifier
 * [in/out] params[1].memref:	Resource table config
 */
#define PTA_QCOM_PAS_GET_RESOURCE_TABLE		5

/*
 * PAS image authentication and co-processor reset.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[0].value.b:	Firmware size
 * [in]  params[1].value.a:	32bit LSB firmware memory address
 * [in]  params[1].value.b:	32bit MSB firmware memory address
 * [in]  params[2].memref:	Optional fw memory space shared/lent
 */
#define PTA_QCOM_PAS_AUTH_AND_RESET		6

/*
 * PAS co-processor set suspend/resume state.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 * [in]  params[0].value.b:	Co-processor state identifier
 */
#define PTA_QCOM_PAS_SET_REMOTE_STATE		7

/*
 * PAS co-processor shutdown.
 *
 * [in]  params[0].value.a:	Unique 32bit remote processor identifier
 */
#define PTA_QCOM_PAS_SHUTDOWN			8

#endif /* __PTA_QCOM_REMOTEPROC_H */
