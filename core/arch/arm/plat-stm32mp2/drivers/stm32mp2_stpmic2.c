// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, STMicroelectronics - All Rights Reserved
 */

#include <config.h>
#include <drivers/regulator.h>
#include <drivers/stm32mp_dt_bindings.h>
#include <drivers/stpmic2.h>
#include <kernel/panic.h>
#include <kernel/pm.h>
#include <platform_config.h>
#include <stm32mp_pm.h>
#include <trace.h>

/*
 * Low power configurations:
 *
 * STM32_PM_DEFAULT
 *   "default" sub nodes in device-tree
 *   is applied at probe, and re-applied at PM resume.
 *   should support STOP1, LP-STOP1, STOP2, LP-STOP2
 *
 * STM32_PM_LPLV
 *   "lplv" sub nodes in device-tree
 *   should support LPLV-STOP1, LPLV-STOP2
 *
 * STM32_PM_STANDBY
 *   "standby" sub nodes in device-tree
 *   should support STANDBY1-DDR-SR
 *   is applied in pm suspend call back
 *
 * STM32_PM_OFF
 *   "off" sub nodes in device-tree
 *   should support STANDBY-DDR-OFF mode
 *   and should be applied before shutdown
 *
 */
#define STM32_PM_DEFAULT		0
#define STM32_PM_LPLV			1
#define STM32_PM_STANDBY		2
#define STM32_PM_OFF			3
#define STM32_PM_NB_SOC_MODES		4

size_t plat_stpmic2_get_lp_mode_count(void)
{
	return STM32_PM_NB_SOC_MODES;
}

const char *plat_stpmic2_get_lp_mode_name(int mode)
{
	switch (mode) {
	case STM32_PM_DEFAULT:
		return "default";
	case STM32_PM_LPLV:
		return "lplv";
	case STM32_PM_STANDBY:
		return "standby";
	case STM32_PM_OFF:
		return "off";
	default:
		EMSG("Invalid lp mode %d", mode);
		panic();
	}
}

static
TEE_Result plat_stpmic2_regu_pm(enum pm_op op, uint32_t pm_hint,
				const struct pm_callback_handle *pm_handle)
{
	struct regulator *regulator = pm_handle->handle;
	unsigned int pwrlvl = PM_HINT_PLATFORM_STATE(pm_hint);
	TEE_Result res = TEE_ERROR_GENERIC;

	if (op == PM_OP_SUSPEND) {
		uint8_t mode = STM32_PM_DEFAULT;

		/* configure STPMIC2 level according MAX PM domain OFF */
		switch (pwrlvl) {
		case PM_D1_LEVEL:
		case PM_D2_LEVEL:
			mode = STM32_PM_LPLV;
			break;
		case PM_D2_LPLV_LEVEL:
			mode = STM32_PM_STANDBY;
			break;
		case PM_MAX_LEVEL:
			mode = STM32_PM_OFF;
			break;
		default:
			mode = STM32_PM_DEFAULT;
			break;
		}

		res = stpmic2_suspend_regulator(regulator, mode);
		if (res)
			return res;

		res = stpmic2_apply_pm_state(regulator, mode);

	} else if (op == PM_OP_RESUME) {
		res = stpmic2_resume_regulator(regulator);
		if (res)
			return res;

		res = stpmic2_apply_pm_state(regulator, STM32_PM_DEFAULT);
	}

	return res;
}

TEE_Result plat_stpmic2_supplied_init(struct regulator *regulator)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = stpmic2_apply_pm_state(regulator, STM32_PM_DEFAULT);
	if (res) {
		EMSG("Failed to prepare regu suspend %s",
		     regulator_name(regulator));
		return res;
	}

	register_pm_core_service_cb(plat_stpmic2_regu_pm, regulator,
				    regulator_name(regulator));

	return TEE_SUCCESS;
}
