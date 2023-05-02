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

#endif /* __PTA_RTC_H */
