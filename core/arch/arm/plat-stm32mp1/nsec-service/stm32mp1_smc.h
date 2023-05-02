/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2016-2022, STMicroelectronics
 * Copyright (c) 2018, Linaro Limited
 */
#ifndef __STM32MP1_SMC_H__
#define __STM32MP1_SMC_H__

#include <sm/optee_smc.h>

/*
 * SIP Functions
 */
#define STM32_SIP_SVC_VERSION_MAJOR	0x0
#define STM32_SIP_SVC_VERSION_MINOR	0x1

#define STM32_SIP_SVC_FUNCTION_COUNT	0x3

/* STM32 SIP service generic return codes */
#define STM32_SIP_SVC_OK		0x0
#define STM32_SIP_SVC_UNKNOWN_FUNCTION	OPTEE_SMC_RETURN_UNKNOWN_FUNCTION
#define STM32_SIP_SVC_FAILED		0xfffffffeU
#define STM32_SIP_SVC_INVALID_PARAMS	0xfffffffdU

/*
 * SMC function IDs for STM32 Service queries
 * STM32 SMC services use the space between 0x82000000 and 0x8200FFFF
 * like this is defined in SMC calling Convention by ARM
 * for SiP (Silicon Partner)
 * http://infocenter.arm.com/help/topic/com.arm.doc.den0028a/index.html
 */

/*
 * SIP function STM32_SIP_FUNC_CALL_COUNT
 *
 * Argument a0: (input) SMCC ID
 *		(output) Count of defined function IDs
 */
#define STM32_SIP_SVC_FUNC_CALL_COUNT		0xff00

/*
 * Return the following UID if using API specified in this file without
 * further extensions:
 * 50aa78a7-9bf4-4a14-8a5e-264d5994c214.
 *
 * Represented in 4 32-bit words in STM32_SIP_UID_0, STM32_SIP_UID_1,
 * STM32_SIP_UID_2, STM32_SIP_UID_3.
 */
#define STM32_SIP_SVC_UID_0			0x50aa78a7
#define STM32_SIP_SVC_UID_1			0x9bf44a14
#define STM32_SIP_SVC_UID_2			0x8a5e264d
#define STM32_SIP_SVC_UID_3			0x5994c214

/*
 * SIP function STM32_SIP_SVC_FUNC_UID
 *
 * Argument a0: (input) SMCC ID
 *		(output) Lowest 32bit of the stm32mp1 SIP service UUID
 * Argument a1: (output) Next 32bit of the stm32mp1 SIP service UUID
 * Argument a2: (output) Next 32bit of the stm32mp1 SIP service UUID
 * Argument a3: (output) Last 32bit of the stm32mp1 SIP service UUID
 */
#define STM32_SIP_SVC_FUNC_UID			0xff01

/*
 * SIP function STM32_SIP_FUNC_VERSION
 *
 * Argument a0: (input) SMCC ID
 *		(output) STM32 SIP service major
 * Argument a1: (output) STM32 SIP service minor
 */
#define STM32_SIP_SVC_FUNC_VERSION		0xff03

/*
 * SIP functions STM32_SIP_SVC_FUNC_BSEC - Deprecated
 *
 * Argument a0: (input) SMCCC function ID
 *		(output) status return code
 * Argument a1: (input) Service ID (STM32_SIP_BSEC_xxx)
 * Argument a2: (input) OTP index
 *		(output) OTP read value, if applicable
 * Argument a3: (input) OTP value if applicable
 */
#define STM32_SIP_SVC_FUNC_BSEC			0x1003

/* Service ID for function ID STM32_SIP_FUNC_BSEC */
#define STM32_SIP_SVC_BSEC_READ_SHADOW		0x1
#define STM32_SIP_SVC_BSEC_PROG_OTP		0x2
#define STM32_SIP_SVC_BSEC_WRITE_SHADOW		0x3
#define STM32_SIP_SVC_BSEC_READ_OTP		0x4
/* reserved for STM32_SIP_SVC_SMC_READ_ALL	0x5 */
/* reserved for STM32_SIP_SVC_SMC_WRITE_ALL	0x6 */
#define STM32_SIP_SVC_BSEC_WRLOCK_OTP		0x7

/*
 * SIP function STM32_SIP_SVC_FUNC_SCMI_AGENT0
 * SIP function STM32_SIP_SVC_FUNC_SCMI_AGENT1
 *
 * Process SCMI message pending in related SCMI shared memory buffer.
 *
 * Argument a0: (input) SMCC ID
 */
#define STM32_SIP_SVC_FUNC_SCMI_AGENT0		0x2000
#define STM32_SIP_SVC_FUNC_SCMI_AGENT1		0x2001

#endif /* __STM32MP1_SMC_H__*/
