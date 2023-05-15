// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 */

#include <assert.h>
#include <drivers/rtc.h>
#include <tee_api_types.h>

struct rtc *rtc_device;

void rtc_register(struct rtc *rtc)
{
	/* One RTC is supported only */
	assert(!rtc_device);

	/* RTC should *at least* allow to get the time */
	assert(rtc && rtc->ops && rtc->ops->get_time);

	rtc_device = rtc;
}
