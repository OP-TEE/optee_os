// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 */

#include <drivers/wdt.h>

struct wdt_chip *wdt_chip;

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
