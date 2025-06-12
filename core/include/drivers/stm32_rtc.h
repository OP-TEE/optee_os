/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018-2025, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RTC_H__
#define __DRIVERS_STM32_RTC_H__

#include <drivers/rtc.h>
#include <stdbool.h>
#include <tee_api_types.h>

#if defined(CFG_STM32_RTC)
/**
 * stm32_rtc_set_tamper_timestamp() - Enable tamper and secure timestamp access
 * in RTC
 */
TEE_Result stm32_rtc_set_tamper_timestamp(void);

/**
 * stm32_rtc_is_timestamp_enabled() - Indicates if RTC timestamping is enabled
 *
 * @ret: [Out] True if and only if RTC timestamp is enabled
 */
TEE_Result stm32_rtc_is_timestamp_enabled(bool *ret);

/**
 * stm32_rtc_get_timestamp() - Get RTC timestamp for current time. This function
 * can be called from an interruption context
 *
 * @tm: [Out] RTC timestamp value
 */
TEE_Result stm32_rtc_get_timestamp(struct optee_rtc_time *tm);

/**
 * stm32_rtc_driver_is_initialized() - Indicates if RTC driver is initialized
 *
 * Returns TEE_ERROR_DEFER_DRIVER_INIT if it's not the case, TEE_SUCCESS
 * otherwise
 */
TEE_Result stm32_rtc_driver_is_initialized(void);
#else /* CFG_STM32_RTC */
static inline TEE_Result stm32_rtc_set_tamper_timestamp(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result stm32_rtc_is_timestamp_enabled(bool *ret __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result
stm32_rtc_get_timestamp(struct optee_rtc_time *tm __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static inline TEE_Result stm32_rtc_driver_is_initialized(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#endif /* CFG_STM32_RTC */
#endif /* __DRIVERS_STM32_RTC_H__ */
