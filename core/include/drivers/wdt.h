/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef __DRIVERS_WDT_H
#define __DRIVERS_WDT_H

#include <assert.h>
#include <kernel/interrupt.h>
#include <kernel/thread.h>
#include <sm/sm.h>
#include <tee_api_types.h>

struct wdt_chip {
	const struct wdt_ops *ops;
	struct itr_handler *wdt_itr;
};

/*
 * struct wdt_ops - The watchdog device operations
 *
 * @init:	The routine to initialized the watchdog resources.
 * @start:	The routine for starting the watchdog device.
 * @stop:	The routine for stopping the watchdog device.
 * @ping:	The routine that sends a keepalive ping to the watchdog device.
 * @set_timeout:The routine that finds the load value that will reset system in
 * required timeout (in seconds).
 *
 * The wdt_ops structure contains a list of low-level operations
 * that control a watchdog device.
 */
struct wdt_ops {
	TEE_Result (*init)(struct wdt_chip *chip, unsigned long *min_timeout,
			   unsigned long *max_timeout);
	void (*start)(struct wdt_chip *chip);
	void (*stop)(struct wdt_chip *chip);
	void (*ping)(struct wdt_chip *chip);
	TEE_Result (*set_timeout)(struct wdt_chip *chip, unsigned long timeout);
};

#ifdef CFG_WDT
extern struct wdt_chip *wdt_chip;

/* Register a watchdog as the system watchdog */
TEE_Result watchdog_register(struct wdt_chip *chip);

static inline
TEE_Result watchdog_init(unsigned long *min_timeout, unsigned long *max_timeout)
{
	if (!wdt_chip)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!wdt_chip->ops->init)
		return TEE_SUCCESS;

	return wdt_chip->ops->init(wdt_chip, min_timeout, max_timeout);
}

static inline void watchdog_start(void)
{
	if (wdt_chip)
		wdt_chip->ops->start(wdt_chip);
}

static inline void watchdog_stop(void)
{
	if (wdt_chip && wdt_chip->ops->stop)
		wdt_chip->ops->stop(wdt_chip);
}

static inline void watchdog_ping(void)
{
	if (wdt_chip)
		wdt_chip->ops->ping(wdt_chip);
}

static inline void watchdog_settimeout(unsigned long timeout)
{
	if (wdt_chip)
		wdt_chip->ops->set_timeout(wdt_chip, timeout);
}
#else
static inline TEE_Result watchdog_register(struct wdt_chip *chip __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline TEE_Result watchdog_init(unsigned long *min_timeout __unused,
				       unsigned long *max_timeout __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

static inline void watchdog_start(void) {}
static inline void watchdog_stop(void) {}
static inline void watchdog_ping(void) {}
static inline void watchdog_settimeout(unsigned long timeout __unused) {}
#endif

#ifdef CFG_WDT_SM_HANDLER
enum sm_handler_ret __wdt_sm_handler(struct thread_smc_args *args);

static inline
enum sm_handler_ret wdt_sm_handler(struct thread_smc_args *args)
{
	if (args->a0 != CFG_WDT_SM_HANDLER_ID)
		return SM_HANDLER_PENDING_SMC;

	return __wdt_sm_handler(args);
}
#else
static inline
enum sm_handler_ret wdt_sm_handler(struct thread_smc_args *args __unused)
{
	return SM_HANDLER_PENDING_SMC;
}
#endif

#endif /* __DRIVERS_WDT_H */
