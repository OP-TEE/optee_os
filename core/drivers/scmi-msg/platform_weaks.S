/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */
#include <arm32_macros.S>
#include <asm.S>
#include <drivers/scmi.h>
#include <kernel/unwind.h>

	/*
	 * Weak functions for SCMI message driver API the platform does
	 * not implement.
	 */

#ifdef CFG_SCMI_MSG_CLOCK
	.weak plat_scmi_clock_count
	.weak plat_scmi_clock_get_name
	.weak plat_scmi_clock_rates_array
	.weak plat_scmi_clock_rates_by_step
	.weak plat_scmi_clock_get_current_rate
	.weak plat_scmi_clock_set_current_rate
	.weak plat_scmi_clock_get_state
	.weak plat_scmi_clock_set_state
#endif

#ifdef CFG_SCMI_MSG_RESET_DOMAIN
	.weak plat_scmi_rd_count
	.weak plat_scmi_rd_get_name
	.weak plat_scmi_rd_autonomous
	.weak plat_scmi_rd_set_state
#endif

/* Unique weak function for unsupported handlers returning SCMI_NOT_SUPPORTED */
FUNC scmi_weak_not_supported , :

#ifdef CFG_SCMI_MSG_CLOCK
plat_scmi_clock_set_current_rate:
plat_scmi_clock_get_state:
plat_scmi_clock_set_state:
plat_scmi_clock_rates_array:
plat_scmi_clock_rates_by_step:
#endif
#ifdef CFG_SCMI_MSG_RESET_DOMAIN
plat_scmi_rd_autonomous:
plat_scmi_rd_set_state:
#endif

UNWIND(	.fnstart)
	ldr	r0, =SCMI_NOT_SUPPORTED
	bx	lr
UNWIND(	.fnend)
END_FUNC scmi_weak_not_supported

/* Unique weak function for unsupported platform handlers returning 0 */
FUNC scmi_server_weak_null , :

#ifdef CFG_SCMI_MSG_CLOCK
plat_scmi_clock_count:
plat_scmi_clock_get_name:
plat_scmi_clock_get_current_rate:
#endif
#ifdef CFG_SCMI_MSG_RESET_DOMAIN
plat_scmi_rd_count:
plat_scmi_rd_get_name:
#endif

UNWIND(	.fnstart)
	ldr	r0, =0
	bx	lr
UNWIND(	.fnend)
END_FUNC scmi_server_weak_null
