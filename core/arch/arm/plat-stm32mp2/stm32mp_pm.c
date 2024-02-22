// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023-2024, STMicroelectronics
 */

#include <kernel/misc.h>
#include <kernel/pm.h>
#include <kernel/thread.h>
#include <sm/psci.h>
#include <stm32mp_pm.h>

/**
 * @brief   Handler for system off
 *
 * @param[in] a0   Unused
 * @param[in] a1   Unused
 *
 * @retval 0       if OK, other value else and TF-A will panic
 */
unsigned long thread_system_off_handler(unsigned long a0 __unused,
					unsigned long a1 __unused)
{
	/*
	 * configure targeted mode in PMIC for system OFF,
	 * no need to save context
	 */
	uint32_t pm_hint = PM_HINT_CLOCK_STATE |
		((PM_MAX_LEVEL << PM_HINT_PLATFORM_STATE_SHIFT) &
		  PM_HINT_PLATFORM_STATE_MASK);

	return pm_change_state(PM_OP_SUSPEND, pm_hint);
}

static uint32_t get_pm_hint(unsigned long a0)
{
	uint32_t pm_hint = 0U;

	/* a0 is the highest power level which was powered down. */
	if (a0 < PM_D2_LPLV_LEVEL)
		pm_hint = PM_HINT_CLOCK_STATE;
	else
		pm_hint = PM_HINT_CONTEXT_STATE;

	pm_hint |= ((a0 << PM_HINT_PLATFORM_STATE_SHIFT) &
		    PM_HINT_PLATFORM_STATE_MASK);

	return pm_hint;
}

/**
 * @brief   Handler for cpu resume
 *
 * @param[in] a0   Max power level powered down
 * @param[in] a1   Unused
 *
 * @retval 0       if OK, other value else and TF-A will panic
 */
unsigned long thread_cpu_resume_handler(unsigned long a0,
					unsigned long a1 __unused)
{
	TEE_Result retstatus = TEE_SUCCESS;

	retstatus = pm_change_state(PM_OP_RESUME, get_pm_hint(a0));

	/*
	 * Returned value to the TF-A.
	 * If it is not 0, the system will panic
	 */
	if (retstatus == TEE_SUCCESS)
		return 0;
	else
		return 1;
}

/**
 * @brief   Handler for cpu suspend
 *
 * @param[in] a0   Max power level to power down
 * @param[in] a1   Unused
 *
 * @retval 0       if OK, other value else and TF-A will panic
 */
unsigned long thread_cpu_suspend_handler(unsigned long a0,
					 unsigned long a1 __unused)
{
	TEE_Result retstatus = TEE_SUCCESS;

	retstatus = pm_change_state(PM_OP_SUSPEND, get_pm_hint(a0));

	/*
	 * Returned value to the TF-A.
	 * If it is not 0, the system will panic
	 */
	if (retstatus == TEE_SUCCESS)
		return 0;
	else
		return 1;
}
