// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Linaro Limited
 */

#include <kernel/callout.h>
#include <kernel/misc.h>
#include <kernel/spinlock.h>
#include <mm/core_memprot.h>

TAILQ_HEAD(callout_head, callout);

static unsigned int callout_sched_lock __nex_data = SPINLOCK_UNLOCK;
static size_t callout_sched_core __nex_bss;
static unsigned int callout_lock __nex_data = SPINLOCK_UNLOCK;
static const struct callout_timer_desc *callout_desc __nex_bss;
static struct callout_head callout_head __nex_data =
	TAILQ_HEAD_INITIALIZER(callout_head);

static void insert_callout(struct callout *co)
{
	struct callout *co2 = NULL;

	TAILQ_FOREACH(co2, &callout_head, link) {
		if (co->expiry_value < co2->expiry_value) {
			TAILQ_INSERT_BEFORE(co2, co, link);
			return;
		}
	}

	TAILQ_INSERT_TAIL(&callout_head, co, link);
}

static void schedule_next_timeout(void)
{
	const struct callout_timer_desc *desc = callout_desc;
	struct callout *co = TAILQ_FIRST(&callout_head);

	if (co)
		desc->set_next_timeout(desc, co->expiry_value);
	else
		desc->disable_timeout(desc);

	if (desc->is_per_cpu) {
		/*
		 * Remember which core is supposed to receive the next
		 * timer interrupt. This will not disable timers on other
		 * CPUs, instead they will be ignored as a spurious call.
		 */
		cpu_spin_lock(&callout_sched_lock);
		callout_sched_core = get_core_pos();
		cpu_spin_unlock(&callout_sched_lock);
	}
}

static bool callout_is_active(struct callout *co)
{
	struct callout *co2 = NULL;

	TAILQ_FOREACH(co2, &callout_head, link)
		if (co2 == co)
			return true;

	return false;
}

void callout_rem(struct callout *co)
{
	uint32_t state = 0;

	state = cpu_spin_lock_xsave(&callout_lock);

	if (callout_is_active(co)) {
		TAILQ_REMOVE(&callout_head, co, link);
		schedule_next_timeout();
	}

	cpu_spin_unlock_xrestore(&callout_lock, state);
}

void callout_add(struct callout *co, bool (*callback)(struct callout *co),
		 uint32_t ms)
{
	const struct callout_timer_desc *desc = callout_desc;
	uint32_t state = 0;

	state = cpu_spin_lock_xsave(&callout_lock);

	assert(is_nexus(co) && !callout_is_active(co) && is_unpaged(callback));
	*co = (struct callout){ .callback = callback, };

	if (desc) {
		co->period = desc->ms_to_ticks(desc, ms);
		co->expiry_value = desc->get_now(desc) + co->period;
	} else {
		/* This will be converted to ticks in callout_service_init(). */
		co->period = ms;
	}

	insert_callout(co);
	if (desc && co == TAILQ_FIRST(&callout_head))
		schedule_next_timeout();

	cpu_spin_unlock_xrestore(&callout_lock, state);
}

void callout_set_next_timeout(struct callout *co, uint32_t ms)
{
	co->period = callout_desc->ms_to_ticks(callout_desc, ms);
}

void callout_service_init(const struct callout_timer_desc *desc)
{
	struct callout_head tmp_head = TAILQ_HEAD_INITIALIZER(tmp_head);
	struct callout *co = NULL;
	uint32_t state = 0;
	uint64_t now = 0;

	state = cpu_spin_lock_xsave(&callout_lock);

	assert(!callout_desc);
	assert(is_nexus(desc) && is_unpaged(desc->disable_timeout) &&
	       is_unpaged(desc->set_next_timeout) &&
	       is_unpaged(desc->ms_to_ticks) && is_unpaged(desc->get_now));

	callout_desc = desc;
	now = desc->get_now(desc);

	TAILQ_CONCAT(&tmp_head, &callout_head, link);
	while (!TAILQ_EMPTY(&tmp_head)) {
		co = TAILQ_FIRST(&tmp_head);
		TAILQ_REMOVE(&tmp_head, co, link);

		/*
		 * Periods set before the timer descriptor are in
		 * milliseconds since the frequency of the timer isn't
		 * available at that point. So update it to ticks now.
		 */
		co->period = desc->ms_to_ticks(desc, co->period);
		co->expiry_value = now + co->period;
		insert_callout(co);
	}
	schedule_next_timeout();

	cpu_spin_unlock_xrestore(&callout_lock, state);
}

void callout_service_cb(void)
{
	const struct callout_timer_desc *desc = callout_desc;
	struct callout *co = NULL;
	uint64_t now = 0;

	if (desc->is_per_cpu) {
		bool do_callout = false;

		/*
		 * schedule_next_timeout() saves the core it was last
		 * called on. If there's a mismatch here it means that
		 * another core has been scheduled for the next callout, so
		 * there's no work to be done for this core and we can
		 * disable the timeout on this CPU.
		 */
		cpu_spin_lock(&callout_sched_lock);
		do_callout = (get_core_pos() == callout_sched_core);
		if (!do_callout)
			desc->disable_timeout(desc);
		cpu_spin_unlock(&callout_sched_lock);
		if (!do_callout)
			return;
	}

	cpu_spin_lock(&callout_lock);

	now = desc->get_now(desc);
	while (!TAILQ_EMPTY(&callout_head)) {
		co = TAILQ_FIRST(&callout_head);
		if (co->expiry_value > now)
			break;

		TAILQ_REMOVE(&callout_head, co, link);

		if (co->callback(co)) {
			co->expiry_value += co->period;
			insert_callout(co);
		}
	}
	schedule_next_timeout();

	cpu_spin_unlock(&callout_lock);
}
