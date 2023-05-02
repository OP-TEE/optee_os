/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Microchip
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>

FUNC at91_pm_cpu_resume, :
UNWIND(	.cantunwind)
	cps	#CPSR_MODE_MON

	blx	plat_cpu_reset_early

	b	sm_pm_cpu_resume
END_FUNC at91_pm_cpu_resume
