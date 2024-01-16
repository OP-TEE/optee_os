/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 Microchip.
 */

#ifndef __DRIVERS_RTC_H
#define __DRIVERS_RTC_H

#include <tee_api_types.h>
#include <util.h>

/* The RTC allows to set/get offset for correction */
#define RTC_CORRECTION_FEATURE	BIT(0)

struct optee_rtc_time {
	uint32_t tm_year;
	uint32_t tm_mon;
	uint32_t tm_mday;
	uint32_t tm_hour;
	uint32_t tm_min;
	uint32_t tm_sec;
	uint32_t tm_wday;
};

struct rtc {
	const struct rtc_ops *ops;
	struct optee_rtc_time range_min;
	struct optee_rtc_time range_max;
};

/*
 * struct rtc_ops - The RTC device operations
 *
 * @get_time:	Get the RTC time.
 * @set_time:	Set the RTC time.
 * @get_offset:	Get the RTC offset.
 * @set_offset: Set the RTC offset
 */
struct rtc_ops {
	TEE_Result (*get_time)(struct rtc *rtc, struct optee_rtc_time *tm);
	TEE_Result (*set_time)(struct rtc *rtc, struct optee_rtc_time *tm);
	TEE_Result (*get_offset)(struct rtc *rtc, long *offset);
	TEE_Result (*set_offset)(struct rtc *rtc, long offset);
};

#ifdef CFG_DRIVERS_RTC
extern struct rtc *rtc_device;

/* Register a RTC device as the system RTC */
void rtc_register(struct rtc *rtc);

static inline TEE_Result rtc_get_info(uint64_t *features,
				      struct optee_rtc_time *range_min,
				      struct optee_rtc_time *range_max)
{
	if (!rtc_device)
		return TEE_ERROR_NOT_SUPPORTED;

	if (rtc_device->ops->set_offset)
		*features = RTC_CORRECTION_FEATURE;
	*range_min = rtc_device->range_min;
	*range_max = rtc_device->range_max;

	return TEE_SUCCESS;
}

static inline TEE_Result rtc_get_time(struct optee_rtc_time *tm)
{
	if (!rtc_device)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->get_time(rtc_device, tm);
}

static inline TEE_Result rtc_set_time(struct optee_rtc_time *tm)
{
	if (!rtc_device || !rtc_device->ops->set_time)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->set_time(rtc_device, tm);
}

static inline TEE_Result rtc_get_offset(long *offset)
{
	if (!rtc_device || !rtc_device->ops->get_offset)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->get_offset(rtc_device, offset);
}

static inline TEE_Result rtc_set_offset(long offset)
{
	if (!rtc_device || !rtc_device->ops->set_offset)
		return TEE_ERROR_NOT_SUPPORTED;

	return rtc_device->ops->set_offset(rtc_device, offset);
}

#else

static inline void rtc_register(struct rtc *rtc __unused) {}

static inline TEE_Result rtc_get_info(uint64_t *features __unused,
				      struct optee_rtc_time *range_min __unused,
				      struct optee_rtc_time *range_max __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_get_time(struct optee_rtc_time *tm __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_set_time(struct optee_rtc_time *tm __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_get_offset(long *offset __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result rtc_set_offset(long offset __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif
#endif /* __DRIVERS_RTC_H */
