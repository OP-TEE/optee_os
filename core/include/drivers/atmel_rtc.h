/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Microchip
 */

#ifndef __DRIVERS_ATMEL_RTC_H
#define __DRIVERS_ATMEL_RTC_H

#include <drivers/rtc.h>
#include <tee_api_types.h>

#ifdef CFG_ATMEL_RTC
TEE_Result atmel_rtc_get_tamper_timestamp(struct optee_rtc_time *tm);
#else
static inline
TEE_Result atmel_rtc_get_tamper_timestamp(struct optee_rtc_time *tm __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif

#endif /* __DRIVERS_ATMEL_RTC_H */
