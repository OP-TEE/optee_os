// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 */

#include <assert.h>
#include <drivers/rtc.h>

/* Time fields shift values to fit date in a 32bit word */
#define RTC_CMP_YEAR_SHIFT	U(26)
#define RTC_CMP_MONTH_SHIFT	U(22)
#define RTC_CMP_DAY_SHIFT	U(17)
#define RTC_CMP_HOUR_SHIFT	U(12)
#define RTC_CMP_MINUTES_SHIFT	U(6)

struct rtc *rtc_device;

static const uint8_t rtc_months_days[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

bool rtc_is_a_leap_year(uint32_t year)
{
	return !(year % 4) && ((year % 100) || !(year % 400));
}

uint8_t rtc_get_month_days(uint32_t month, uint32_t year)
{
	if (rtc_is_a_leap_year(year) && month == 1)
		return rtc_months_days[month] + 1;
	else
		return rtc_months_days[month];
}

int rtc_timecmp(struct optee_rtc_time *a, struct optee_rtc_time *b)
{
	uint64_t tm_a = 0;
	uint64_t tm_b = 0;

	tm_a = SHIFT_U64(a->tm_year, RTC_CMP_YEAR_SHIFT) +
	       SHIFT_U64(a->tm_mon, RTC_CMP_MONTH_SHIFT) +
	       SHIFT_U64(a->tm_mday, RTC_CMP_DAY_SHIFT) +
	       SHIFT_U64(a->tm_hour, RTC_CMP_HOUR_SHIFT) +
	       SHIFT_U64(a->tm_min, RTC_CMP_MINUTES_SHIFT) +
	       a->tm_sec;
	tm_b = SHIFT_U64(b->tm_year, RTC_CMP_YEAR_SHIFT) +
	       SHIFT_U64(b->tm_mon, RTC_CMP_MONTH_SHIFT) +
	       SHIFT_U64(b->tm_mday, RTC_CMP_DAY_SHIFT) +
	       SHIFT_U64(b->tm_hour, RTC_CMP_HOUR_SHIFT) +
	       SHIFT_U64(b->tm_min, RTC_CMP_MINUTES_SHIFT) +
	       b->tm_sec;

	if (tm_a == tm_b)
		return CMP_TRILEAN(a->tm_subs, b->tm_subs);

	return CMP_TRILEAN(tm_a, tm_b);
}

void rtc_register(struct rtc *rtc)
{
	/* One RTC is supported only */
	assert(!rtc_device);

	/* RTC should *at least* allow to get the time */
	assert(rtc && rtc->ops && rtc->ops->get_time);

	rtc_device = rtc;
}
