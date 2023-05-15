// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <arm64.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>

static unsigned int timer_lock = SPINLOCK_UNLOCK;
static bool timer_running;

void generic_timer_start(uint32_t time_ms)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	uint32_t timer_ticks;

	cpu_spin_lock(&timer_lock);

	if (timer_running == true)
		goto exit;

	/* The timer will fire time_ms from now */
	timer_ticks = (read_cntfrq() * time_ms) / 1000;
	write_cntps_tval(timer_ticks);

	/* Enable the secure physical timer */
	write_cntps_ctl(1);

	timer_running = true;

exit:
	cpu_spin_unlock(&timer_lock);
	thread_set_exceptions(exceptions);
}

void generic_timer_stop(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);

	cpu_spin_lock(&timer_lock);

	/* Disable the timer */
	write_cntps_ctl(0);

	timer_running = false;

	cpu_spin_unlock(&timer_lock);
	thread_set_exceptions(exceptions);
}

void generic_timer_handler(uint32_t time_ms)
{
	uint32_t timer_ticks;

	/* Ensure that the timer did assert the interrupt */
	assert((read_cntps_ctl() >> 2));

	/* Disable the timer */
	write_cntps_ctl(0);

	/* Reconfigure timer to fire time_ms from now */
	timer_ticks = (read_cntfrq() * time_ms) / 1000;
	write_cntps_tval(timer_ticks);

	/* Enable the secure physical timer */
	write_cntps_ctl(1);
}
