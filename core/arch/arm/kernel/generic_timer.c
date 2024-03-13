// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Linaro Limited
 */

#include <arm.h>
#include <kernel/callout.h>
#include <kernel/timer.h>

static void timer_disable(const struct callout_timer_desc *desc __unused)
{
	write_cntps_ctl(0);
}

static void timer_set_next(const struct callout_timer_desc *desc __unused,
			   uint64_t ctrval)
{
	write_cntps_cval(ctrval);
	write_cntps_ctl(1);
}

static uint64_t
timer_ms_to_ticks(const struct callout_timer_desc *desc __unused,
		  uint32_t timeout_ms)
{
	uint64_t freq = read_cntfrq();

	return (freq * timeout_ms) / 1000;
}

static uint64_t timer_now(const struct callout_timer_desc *desc __unused)
{
	return barrier_read_counter_timer();
}

static struct itr_handler timer_itr __nex_bss;
static const struct callout_timer_desc timer_desc
__relrodata_unpaged("timer_desc") = {
	.disable_timeout = timer_disable,
	.set_next_timeout = timer_set_next,
	.ms_to_ticks = timer_ms_to_ticks,
	.get_now = timer_now,
	.is_per_cpu = true,
};
DECLARE_KEEP_PAGER(timer_desc);

static enum itr_return timer_itr_cb(struct itr_handler *h __unused)
{
	callout_service_cb();

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(timer_itr_cb);

void timer_init_callout_service(struct itr_chip *itr_chip, size_t itr_number)
{
	timer_itr = (struct itr_handler){
		.it = itr_number,
		.flags = ITRF_TRIGGER_LEVEL,
		.handler = timer_itr_cb,
	};

	if (interrupt_add_handler_with_chip(itr_chip, &timer_itr))
		panic();

	interrupt_enable(timer_itr.chip, timer_itr.it);
	callout_service_init(&timer_desc);
}
