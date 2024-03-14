// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <kernel/tee_time.h>
#include <kernel/mutex.h>

static TEE_Time prev;

static struct mutex time_mu = MUTEX_INITIALIZER;

TEE_Result tee_time_get_sys_time(TEE_Time *time)
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

uint32_t tee_time_get_sys_time_protection_level(void)
{
	return 100;
}
