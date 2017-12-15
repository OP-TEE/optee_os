// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <kernel/tee_time.h>
#include <kernel/time_source.h>
#include <kernel/mutex.h>

static TEE_Time prev;

static struct mutex time_mu = MUTEX_INITIALIZER;

static TEE_Result get_monotonic_ree_time(TEE_Time *time)
{
	TEE_Result res;

	res = tee_time_get_ree_time(time);
	if (res != TEE_SUCCESS)
		return res;

	mutex_lock(&time_mu);
	if (time->seconds < prev.seconds ||
		(time->seconds == prev.seconds &&
		 time->millis < prev.millis))
		*time = prev; /* REE time was rolled back */
	else
		prev = *time;
	mutex_unlock(&time_mu);

	return res;
}

static const struct time_source ree_time_source = {
	.name = "ree",
	.protection_level = 100,
	.get_sys_time = get_monotonic_ree_time,
};

REGISTER_TIME_SOURCE(ree_time_source)
