/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026, STMicroelectronics - All Rights Reserved
 */

#ifndef __PTA_STM32MP_DEBUG_ACCESS_H
#define __PTA_STM32MP_DEBUG_ACCESS_H

#define PTA_STM32_DBG_ACCESS_UUID \
	{ 0xdd05bc8b, 0x9f3b, 0x49f0, \
	 { 0xb6, 0x49, 0x01, 0xaa, 0x10, 0xc1, 0xc2, 0x10 } }

enum stm32_pta_dbg_profile {
	/* Embedded debug peripherals support */
	PTA_STM32_DEBUG_PERIPHERAL_DBG_PROFILE = 0,
	/* Hardware Debug Port (HDP) support (internal signals observation) */
	PTA_STM32_DEBUG_HDP_DBG_PROFILE = 1,
};

/**
 * PTA_STM32_DEBUG_CMD_GRANT_DBG_ACCESS
 *
 * [in]		value[0].a	Debug configuration to grant access to.
 *				See enum stm32_pta_dbg_profile.
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_ACCESS_DENIED - Debug services access not granted
 */
#define PTA_STM32_DEBUG_CMD_GRANT_DBG_ACCESS	0x0

#endif /* __PTA_STM32MP_DEBUG_ACCESS_H */
