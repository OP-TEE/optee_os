/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2019 Broadcom.
 */

#ifndef DRIVERS_WDT_H
#define DRIVERS_WDT_H

#include <kernel/interrupt.h>
#include <mm/core_memprot.h>

struct wdt_chip {
	struct wdt_ops *ops;
	struct itr_handler wdt_irq;
};

struct wdt_ops {
	void (*start)(struct wdt_chip *chip);
	void (*stop)(struct wdt_chip *chip);
	void (*ping)(struct wdt_chip *chip);
	void (*set_timeout)(struct wdt_chip *chip, unsigned long timeout);
};

#endif /* DRIVERS_WDT_H */
