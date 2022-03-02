// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 * Copyright (c) 2022 Linaro Limited
 */

#include <config.h>
#include <drivers/wdt.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <stdint.h>

struct wdt_chip *wdt_chip;

#ifdef CFG_WDT_EXTEND_TIMEOUT

#ifndef CFG_CORE_HAS_GENERIC_TIMER
#error CFG_WDT_EXTEND_TIMEOUT currently mandates CFG_CORE_HAS_GENERIC_TIMER
#endif

/*
 * Extended non-secure watchdog timeout
 * @end_cnt - Counter end value until which watchdog must be refreshed
 * @refresh_ms - Watchdog refresh timer rate in milliseconds
 * @lock - Currentl protection on struct and generic timer access
 */
struct extend_timeout {
	uint64_t end_cnt;
	unsigned int refresh_ms;
	unsigned int lock;
};

static struct extend_timeout extended_timeout = {
	.lock = SPINLOCK_UNLOCK,
};

static enum itr_return wdt_arm_cntp_itr_cb(struct itr_handler *handler __unused)
{
	uint64_t __maybe_unused ext_to = 0;
	uint64_t cntpct = 0;
	uint32_t exceptions = 0;

	/* Ensure consistency of @iwdg content and generic timer control */
	exceptions = cpu_spin_lock_xsave(&extended_timeout.lock);

	cntpct = barrier_read_counter_timer();
	if (wdt_chip && cntpct < extended_timeout.end_cnt) {
		ext_to = (extended_timeout.end_cnt - cntpct) / read_cntfrq();

		if (generic_timer_handler(extended_timeout.refresh_ms))
			panic("reload arm cntp");

		wdt_chip->ops->ping(wdt_chip);
	} else {
		generic_timer_stop();
	}

	cpu_spin_unlock_xrestore(&extended_timeout.lock, exceptions);

	if (ext_to)
		DMSG("Extending watchdog timeout for %"PRIu64"s", ext_to);
	else
		DMSG("Stop extending watchdog timeout");

	return ITRR_HANDLED;
}
DECLARE_KEEP_PAGER(wdt_arm_cntp_itr_cb);

static bool supports_extend_timeout(void)
{
	return wdt_chip && wdt_chip->ops->get_timeout;
}

/*
 * Platform can override this function when platform constraints make
 * periodic timer interrupt not always available.
 */
bool __weak watchdog_extend_timeout_timer_is_available(void)
{
	return true;
}

unsigned long watchdog_extend_timeout_max(void)
{
	if (!supports_extend_timeout())
		return 0;

	return CFG_WDT_EXTEND_TIMEOUT_MAX_SEC;
}

TEE_Result watchdog_extend_timeout(unsigned long delay_seconds)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	unsigned long timeout = 0;
	uint32_t exceptions = 0;
	uint64_t cnt = 0;

	if (!delay_seconds) {
		DMSG("Stop extending watchdog timeout");

		exceptions = cpu_spin_lock_xsave(&extended_timeout.lock);

		generic_timer_stop();

		extended_timeout.end_cnt = 0;
		extended_timeout.refresh_ms = 0;

		cpu_spin_unlock_xrestore(&extended_timeout.lock, exceptions);

		return TEE_SUCCESS;
	}

	if (!supports_extend_timeout())
		return TEE_ERROR_NOT_SUPPORTED;

	if (!watchdog_extend_timeout_timer_is_available())
		return TEE_ERROR_BAD_STATE;

	if (delay_seconds > CFG_WDT_EXTEND_TIMEOUT_MAX_SEC)
		return TEE_ERROR_BAD_PARAMETERS;

	if (extended_timeout.end_cnt) {
		EMSG("On-going timeout extension");
		return TEE_ERROR_BAD_STATE;
	}

	wdt_chip->ops->ping(wdt_chip);

	timeout = wdt_chip->ops->get_timeout(wdt_chip);
	if (timeout > delay_seconds)
		return TEE_SUCCESS;

	cnt = read_cntfrq();
	if (MUL_OVERFLOW(delay_seconds, cnt, &cnt) ||
	    ADD_OVERFLOW(barrier_read_counter_timer(), cnt, &cnt))
		return TEE_ERROR_BAD_PARAMETERS;

	exceptions = cpu_spin_lock_xsave(&extended_timeout.lock);

	extended_timeout.end_cnt = cnt;
	extended_timeout.refresh_ms = timeout * 1000 / 2;

	res = generic_timer_start(extended_timeout.refresh_ms);

	cpu_spin_unlock_xrestore(&extended_timeout.lock, exceptions);

	if (res)
		return res;

	DMSG("Extending watchdog for %lus", delay_seconds);

	return TEE_SUCCESS;
}

static TEE_Result watchdog_extend_timeout_init(void)
{
	static struct itr_handler wdt_arm_cntp_itr = {
		.it = CFG_GENERIC_TIMER_GIC_INTD,
		.handler = wdt_arm_cntp_itr_cb,
	};

	COMPILE_TIME_ASSERT(CFG_GENERIC_TIMER_GIC_INTD != 0);

	if (!watchdog_extend_timeout_timer_is_available()) {
		EMSG("Timer not available");
		return TEE_ERROR_GENERIC;
	}

	itr_add(&wdt_arm_cntp_itr);
	itr_enable(wdt_arm_cntp_itr.it);

	return TEE_SUCCESS;
}

driver_init(watchdog_extend_timeout_init);
#endif /* CFG_WDT_EXTEND_TIMEOUT */

TEE_Result watchdog_register(struct wdt_chip *chip)
{
	if (wdt_chip) {
		DMSG("Cannot register several watchdog instances");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!chip->ops->start || !chip->ops->ping  || !chip->ops->set_timeout)
		return TEE_ERROR_BAD_PARAMETERS;

	wdt_chip = chip;

	return TEE_SUCCESS;
}
