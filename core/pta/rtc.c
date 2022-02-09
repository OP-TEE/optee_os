// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018, Linaro Limited
 * Copyright (c) 2021, EPAM Systems. All rights reserved.
 * Copyright (c) 2022, Microchip
 *
 */

#include <drivers/rtc.h>
#include <kernel/pseudo_ta.h>
#include <pta_rtc.h>
#include <string.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>

#define PTA_NAME "rtc.pta"

static void rtc_pta_copy_time_from_optee(struct pta_rtc_time *pta_time,
					 struct optee_rtc_time *optee_time)
{
	pta_time->tm_sec = optee_time->tm_sec;
	pta_time->tm_min = optee_time->tm_min;
	pta_time->tm_hour = optee_time->tm_hour;
	pta_time->tm_mday = optee_time->tm_mday;
	pta_time->tm_mon = optee_time->tm_mon;
	pta_time->tm_year = optee_time->tm_year;
	pta_time->tm_wday = optee_time->tm_wday;
}

static TEE_Result rtc_pta_get_time(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct optee_rtc_time time = { };
	struct pta_rtc_time *pta_time = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	pta_time = params[0].memref.buffer;
	if (!pta_time || params[0].memref.size != sizeof(*pta_time))
		return TEE_ERROR_BAD_PARAMETERS;

	res = rtc_get_time(&time);
	if (res)
		return res;

	rtc_pta_copy_time_from_optee(pta_time, &time);

	return TEE_SUCCESS;
}

static TEE_Result rtc_pta_set_time(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	struct optee_rtc_time time = { };
	struct pta_rtc_time *pta_time = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	pta_time = params[0].memref.buffer;
	if (!pta_time || params[0].memref.size != sizeof(*pta_time))
		return TEE_ERROR_BAD_PARAMETERS;

	time.tm_sec = pta_time->tm_sec;
	time.tm_min = pta_time->tm_min;
	time.tm_hour = pta_time->tm_hour;
	time.tm_mday = pta_time->tm_mday;
	time.tm_mon = pta_time->tm_mon;
	time.tm_year = pta_time->tm_year;
	time.tm_wday = pta_time->tm_wday;

	return rtc_set_time(&time);
}

static TEE_Result rtc_pta_set_offset(uint32_t types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	return rtc_set_offset((int32_t)params[0].value.a);
}

static TEE_Result rtc_pta_get_offset(uint32_t types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	long offset = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = rtc_get_offset(&offset);
	if (res)
		return res;

	if (offset > INT32_MAX || offset < INT32_MIN)
		return TEE_ERROR_OVERFLOW;

	params[0].value.a = (uint32_t)offset;

	return res;
}

static TEE_Result rtc_pta_get_info(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct pta_rtc_info *info = NULL;
	struct optee_rtc_time range_min = { };
	struct optee_rtc_time range_max = { };
	uint64_t features = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	info = params[0].memref.buffer;
	if (!info || params[0].memref.size != sizeof(*info))
		return TEE_ERROR_BAD_PARAMETERS;

	memset(info, 0, sizeof(*info));

	res = rtc_get_info(&features, &range_min, &range_max);
	if (res)
		return res;

	info->version = PTA_RTC_INFO_VERSION;

	if (features & RTC_CORRECTION_FEATURE)
		info->features |= PTA_RTC_FEATURE_CORRECTION;

	rtc_pta_copy_time_from_optee(&info->range_min, &range_min);
	rtc_pta_copy_time_from_optee(&info->range_max, &range_max);

	return TEE_SUCCESS;
}

static TEE_Result open_session(uint32_t ptypes __unused,
			       TEE_Param par[TEE_NUM_PARAMS] __unused,
			       void **session __unused)
{
	struct ts_session *ts = ts_get_current_session();
	struct tee_ta_session *ta_session = to_ta_session(ts);

	/* Only REE kernel is allowed to access RTC */
	if (ta_session->clnt_id.login != TEE_LOGIN_REE_KERNEL)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RTC_GET_INFO:
		return rtc_pta_get_info(ptypes, params);
	case PTA_CMD_RTC_GET_TIME:
		return rtc_pta_get_time(ptypes, params);
	case PTA_CMD_RTC_SET_TIME:
		return rtc_pta_set_time(ptypes, params);
	case PTA_CMD_RTC_GET_OFFSET:
		return rtc_pta_get_offset(ptypes, params);
	case PTA_CMD_RTC_SET_OFFSET:
		return rtc_pta_set_offset(ptypes, params);
	default:
		break;
	}

	return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_RTC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_CONCURRENT |
			    TA_FLAG_DEVICE_ENUM,
		   .open_session_entry_point = open_session,
		   .invoke_command_entry_point = invoke_command);
