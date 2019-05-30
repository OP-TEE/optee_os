/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef DRIVERS_WDT_H
#define DRIVERS_WDT_H

#include <kernel/interrupt.h>
#include <tee_api_types.h>

struct wdt_chip {
	const struct wdt_ops *ops;
	struct itr_handler *wdt_itr;
};

/*
 * struct wdt_ops - The watchdog device operations
 *
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
	void (*start)(struct wdt_chip *chip);
	void (*stop)(struct wdt_chip *chip);
	void (*ping)(struct wdt_chip *chip);
	TEE_Result (*set_timeout)(struct wdt_chip *chip, unsigned long timeout);
};

#endif /* DRIVERS_WDT_H */
