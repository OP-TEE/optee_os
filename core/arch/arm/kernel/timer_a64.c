// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2022, Linaro Limited
 */

#include <arm64.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <tee_api_types.h>

static unsigned int timer_lock = SPINLOCK_UNLOCK;
static bool timer_running;

TEE_Result generic_timer_start(uint32_t time_ms)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&timer_lock);
	uint32_t timer_ticks = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (timer_running) {
		res = TEE_ERROR_BUSY;
		goto exit;
	}

	/* The timer will fire time_ms from now */
	timer_ticks = (read_cntfrq() * time_ms) / 1000;
	write_cntps_tval(timer_ticks);

	/* Enable the secure physical timer */
	write_cntps_ctl(1);

	timer_running = true;

	res = TEE_SUCCESS;

exit:
	cpu_spin_unlock_xrestore(&timer_lock, exceptions);

	return res;
}

TEE_Result generic_timer_stop(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&timer_lock);

	/* Disable the timer */
	write_cntps_ctl(0);

	timer_running = false;

	cpu_spin_unlock_xrestore(&timer_lock, exceptions);

	return TEE_SUCCESS;
}

TEE_Result generic_timer_handler(uint32_t time_ms)
{
	uint32_t timer_ticks = 0;

	/* Ensure that the timer did assert the interrupt */
	assert((read_cntps_ctl() >> 2));

	/* Disable the timer */
	write_cntps_ctl(0);

	/* Reconfigure timer to fire time_ms from now */
	timer_ticks = (read_cntfrq() * time_ms) / 1000;
	write_cntps_tval(timer_ticks);

	/* Enable the secure physical timer */
	write_cntps_ctl(1);

	return TEE_SUCCESS;
}
