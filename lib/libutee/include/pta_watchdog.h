/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019-2021, Linaro Limited
 */
#ifndef PTA_WATCHDOG_H
#define PTA_WATCHDOG_H

#define PTA_WATCHDOG_UUID \
	{ 0xa8cfe406, 0xd4f5, 0x4a2e, \
	  { 0x9f, 0x8d, 0xa2, 0x5d, 0xc7, 0x54, 0xc0, 0xa9 } }

#define PTA_WATCHDOG_NAME	"PTA-WATCHDOG"

/*
 * PTA_WATCHDOG_CMD_CONFIG - Configure watchdog
 *
 * [in]     value[0].a: Watchdog timeout in seconds
 */
#define PTA_WATCHDOG_CMD_CONFIG		0

/*
 * PTA_WATCHDOG_CMD_START - Start watchdog
 */
#define PTA_WATCHDOG_CMD_START		1

/*
 * PTA_WATCHDOG_CMD_PIN - Refresh watchdog
 */
#define PTA_WATCHDOG_CMD_PING		2

/*
 * PTA_WATCHDOG_CMD_STOP - Stop watchdog
 */
#define PTA_WATCHDOG_CMD_STOP		3

/*
 * PTA_WATCHDOG_CMD_SET_TIMEOUT - Set watchdog timeout
 *
 * [in]     value[0].a: Watchdog timeout in seconds
 */
#define PTA_WATCHDOG_CMD_SET_TIMEOUT	4

/*
 * PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_CAPS - Extended tiemout capabilities
 *
 * [out]    value[0].a: Max extended watchdog timeout in seconds or 0
 * [out]    value[0].b: Reserved, must be 0.
 * [out]    value[1].a: Reserved, must be 0.
 * [out]    value[1].b: Reserved, must be 0.
 */
#define PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_CAPS	5

/*
 * PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_START - Start extending watchdog timeout
 *
 * [in]     value[0].a: Requested extended timeout in seconds
 */
#define PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_START	6

/*
 * PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_STOP - Stop extending watchdog timeout
 */
#define PTA_WATCHDOG_CMD_EXTEND_TIMEOUT_STOP	7

#endif /* PTA_WATCHDOG_H */
