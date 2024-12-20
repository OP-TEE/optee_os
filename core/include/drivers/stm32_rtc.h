/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2018-2024, STMicroelectronics
 */

#ifndef __DRIVERS_STM32_RTC_H
#define __DRIVERS_STM32_RTC_H

#include <drivers/rtc.h>

#if defined(CFG_STM32_RTC)
/*
 * Return time diff in milliseconds between current and reference time
 * System will panic if stm32_rtc_calendar "cur" is older than "ref".
 */
unsigned long long stm32_rtc_diff_calendar_ms(struct optee_rtc_time *cur,
					      struct optee_rtc_time *ref);

/*
 * Return time diff in tick count between current and reference time
 * System will panic if stm32_rtc_calendar "cur" is older than "ref".
 */
unsigned long long stm32_rtc_diff_calendar_tick(struct optee_rtc_time *cur,
						struct optee_rtc_time *ref,
						unsigned long long tick_rate);
#else /* defined(CFG_STM32_RTC) */
static inline unsigned long long
stm32_rtc_diff_calendar_ms(struct optee_rtc_time *cur __unused,
			   struct optee_rtc_time *ref __unused)
{
	return ULLONG_MAX;
}

static inline unsigned long long
stm32_rtc_diff_calendar_tick(struct optee_rtc_time *cur __unused,
			     struct optee_rtc_time *ref __unused,
			     unsigned long long tick_rate __unused)
{
	return ULLONG_MAX;
}
#endif /* defined(CFG_STM32_RTC) */
#endif /* __DRIVERS_STM32_RTC_H */
