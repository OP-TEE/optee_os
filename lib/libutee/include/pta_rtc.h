/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022, Microchip
 */
#ifndef __PTA_RTC_H
#define __PTA_RTC_H

#include <tee_api_types.h>

#define PTA_RTC_UUID { 0xf389f8c8, 0x845f, 0x496c, \
		{ 0x8b, 0xbe, 0xd6, 0x4b, 0xd2, 0x4c, 0x92, 0xfd } }

#define PTA_RTC_INFO_VERSION		0x1

/*
 * RTC provides set/get offset and thus command PTA_CMD_RTC_GET_OFFSET and
 * PTA_CMD_RTC_SET_OFFSET might be called
 */
#define PTA_RTC_FEATURE_CORRECTION	BIT(0)

/*
 * RTC provides set/read/enable/wait alarm and thus
 * commands:
 * PTA_CMD_RTC_SET_ALARM, PTA_CMD_RTC_READ_ALARM,
 * PTA_CMD_RTC_WAIT_ALARM, PTA_CMD_RTC_ENABLE_ALARM
 * might be called
 */
#define PTA_RTC_FEATURE_ALARM		BIT(1)

/*
 * Command PTA_CMD_RTC_SET_WAKE_ALARM_STATUS can be used to enable/disable the
 * alarm wake-up capability.
 */
#define PTA_RTC_FEATURE_WAKEUP_ALARM	BIT(2)

struct pta_rtc_time {
	uint32_t tm_sec;
	uint32_t tm_min;
	uint32_t tm_hour;
	uint32_t tm_mday;
	uint32_t tm_mon;
	uint32_t tm_year;
	uint32_t tm_wday;
};

/*
 * struct pta_rtc_alarm - State of an RTC alarm
 * @enabled - 1 if alarm is enabled, 0 if disabled
 * @pending - 1 if alarm event is pending, 0 if not
 * @time: Alarm elapsure time
 */
struct pta_rtc_alarm {
	uint8_t enabled;
	uint8_t pending;
	struct pta_rtc_time time;
};

/*
 * struct pta_rtc_info - RTC service information
 * @version - 1st 64bit cell, version of the structure: PTA_RTC_INFO_VERSION
 * @features - 64bit flag mask related to PTA_RTC_FEATURE_*
 * @range_min - Minima time reference the RTC can be programmed to
 * @range_max - Maxima time reference the RTC can reach
 */
struct pta_rtc_info {
	uint64_t version;
	uint64_t features;
	struct pta_rtc_time range_min;
	struct pta_rtc_time range_max;
};

/*
 * PTA_CMD_RTC_GET_INFO - Get RTC information
 *
 * [out]        memref[0]  RTC buffer memory reference containing a struct
 *			   pta_rtc_info
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_GET_INFO	0x0

/*
 * PTA_CMD_RTC_GET_TIME - Get time from RTC
 *
 * [out]    memref[0]  RTC buffer memory reference containing a struct
 *		       pta_rtc_time
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_GET_TIME		0x1

/*
 * PTA_CMD_RTC_SET_TIME - Set time from RTC
 *
 * [in]     memref[0]  RTC buffer memory reference containing a struct
 *                     pta_rtc_time to be used as RTC time
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_SET_TIME		0x2

/*
 * PTA_CMD_RTC_GET_OFFSET - Get RTC offset
 *
 * [out]    value[0].a  RTC offset (signed 32bit value)
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_GET_OFFSET		0x3

/*
 * PTA_CMD_RTC_SET_OFFSET - Set RTC offset
 *
 * [in]     value[0].a  RTC offset to be set (signed 32bit value)
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_SET_OFFSET		0x4

/*
 * PTA_CMD_RTC_READ_ALARM - Read RTC alarm
 *
 * [out]     memref[0]  RTC buffer memory reference containing a struct
 *                      pta_rtc_alarm
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_READ_ALARM		0x5

/*
 * PTA_CMD_RTC_SET_ALARM - Set RTC alarm
 *
 * [in]     memref[0]  RTC buffer memory reference containing a struct
 *                     pta_rtc_alarm to be used as RTC alarm
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_SET_ALARM		0x6

/*
 * PTA_CMD_RTC_ENABLE_ALARM - Enable Alarm
 *
 * [in]     value[0].a  RTC IRQ flag (uint32_t), 0 to disable the alarm, 1 to
 *                      enable
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_ENABLE_ALARM	0x7

/*
 * PTA_CMD_RTC_WAIT_ALARM - Get alarm event
 *
 * [out]     value[0].a  RTC wait alarm return status (uint32_t):
 *                       - 0: No alarm event
 *                       - 1: Alarm event occurred
 *                       - 2: Alarm event canceled
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_WAIT_ALARM		0x8

/*
 * PTA_CMD_RTC_CANCEL_WAIT - Cancel wait for alarm event
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_CANCEL_WAIT		0x9

/*
 * PTA_CMD_RTC_SET_WAKE_ALARM_STATUS - Set RTC wake alarm status flag
 *
 * [in]     value[0].a RTC IRQ wake alarm flag (uint32_t), 0 to disable the wake
 *                     up capability, 1 to enable.
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 */
#define PTA_CMD_RTC_SET_WAKE_ALARM_STATUS	0xA

#endif /* __PTA_RTC_H */
