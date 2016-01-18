/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
