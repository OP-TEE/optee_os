// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <arm32.h>
#include <kernel/spinlock.h>
#include <kernel/thread.h>
#include <kernel/timer.h>
#include <stdbool.h>
#include <tee_api_types.h>
#include <util.h>

#define CNTP_CTL_ENABLE		BIT(0)
#define CNTP_CTL_IMASK		BIT(1)
#define CNTP_CTL_ISTATUS	BIT(2)

static unsigned int timer_lock = SPINLOCK_UNLOCK;
static bool timer_running;

static TEE_Result reload_timer(uint32_t time_ms)
{
	uint64_t mult = ((uint64_t)read_cntfrq() * time_ms) / 1000;
	uint32_t timer_ticks = mult;

	if (read_cntp_ctl() & CNTP_CTL_ISTATUS)
		return TEE_ERROR_GENERIC;

	if (read_cntp_ctl() & CNTP_CTL_ENABLE)
		return TEE_ERROR_BAD_STATE;

	if (!mult || mult > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	write_cntp_ctl(read_cntp_ctl() & ~(CNTP_CTL_ENABLE | CNTP_CTL_IMASK));
	write_cntp_tval(timer_ticks);
	write_cntp_ctl(read_cntp_ctl() | CNTP_CTL_ENABLE);

	return TEE_SUCCESS;
}

TEE_Result generic_timer_start(uint32_t time_ms)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;

	exceptions = cpu_spin_lock_xsave(&timer_lock);

	if (timer_running) {
		res = TEE_ERROR_BUSY;
		goto exit;
	}

	res = reload_timer(time_ms);
	if (res)
		goto exit;

	timer_running = true;

exit:
	cpu_spin_unlock_xrestore(&timer_lock, exceptions);

	return res;
}

TEE_Result generic_timer_stop(void)
{
	uint32_t exceptions = cpu_spin_lock_xsave(&timer_lock);

	write_cntp_ctl(read_cntp_ctl() & ~(CNTP_CTL_ENABLE | CNTP_CTL_IMASK));

	timer_running = false;

	cpu_spin_unlock_xrestore(&timer_lock, exceptions);

	return TEE_SUCCESS;
}

TEE_Result generic_timer_handler(uint32_t time_ms)
{
	/* This is expected to be called from the timer interrutp service */
	if ((read_cntp_ctl() & CNTP_CTL_ISTATUS) == 0) {
		EMSG("Timer interrupt asserted");
		return TEE_ERROR_GENERIC;
	}

	/* Disable then re-arm the timer */
	write_cntp_ctl(read_cntp_ctl() & ~(CNTP_CTL_ENABLE | CNTP_CTL_IMASK));

	return reload_timer(time_ms);
}
