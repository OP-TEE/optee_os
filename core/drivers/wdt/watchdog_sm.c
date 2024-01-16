// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 Microchip
 */

#include <drivers/wdt.h>
#include <kernel/spinlock.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <sm/watchdog_smc.h>

static unsigned long wdt_min_timeout;
static unsigned long wdt_max_timeout;
/* Lock for timeout variables */
static unsigned int wdt_lock = SPINLOCK_UNLOCK;

enum sm_handler_ret __wdt_sm_handler(struct thread_smc_args *args)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t exceptions = 0;
	unsigned long min_timeout = 0;
	unsigned long max_timeout = 0;

	switch (args->a1) {
	case SMCWD_INIT:
		exceptions = cpu_spin_lock_xsave(&wdt_lock);
		res = watchdog_init(&wdt_min_timeout, &wdt_max_timeout);
		cpu_spin_unlock_xrestore(&wdt_lock, exceptions);

		if (res) {
			args->a0 = PSCI_RET_INTERNAL_FAILURE;
		} else {
			args->a0 = PSCI_RET_SUCCESS;
			args->a1 = wdt_min_timeout;
			args->a2 = wdt_max_timeout;
		}
		break;
	case SMCWD_SET_TIMEOUT:
		exceptions = cpu_spin_lock_xsave(&wdt_lock);
		min_timeout = wdt_min_timeout;
		max_timeout = wdt_max_timeout;
		cpu_spin_unlock_xrestore(&wdt_lock, exceptions);

		if (args->a2 < min_timeout || args->a2 > max_timeout) {
			args->a0 = PSCI_RET_INVALID_PARAMETERS;
			break;
		}

		watchdog_settimeout(args->a2);
		args->a0 = PSCI_RET_SUCCESS;
		break;
	case SMCWD_ENABLE:
		if (args->a2 == 0) {
			watchdog_stop();
			args->a0 = PSCI_RET_SUCCESS;
		} else if (args->a2 == 1) {
			watchdog_start();
			args->a0 = PSCI_RET_SUCCESS;
		} else {
			args->a0 = PSCI_RET_INVALID_PARAMETERS;
		}
		break;
	case SMCWD_PET:
		watchdog_ping();
		args->a0 = PSCI_RET_SUCCESS;
		break;
	/* SMCWD_GET_TIMELEFT is optional */
	case SMCWD_GET_TIMELEFT:
	default:
		args->a0 = PSCI_RET_NOT_SUPPORTED;
	}

	return SM_HANDLER_SMC_HANDLED;
}
