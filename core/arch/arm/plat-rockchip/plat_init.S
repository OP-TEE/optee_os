/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017, Fuzhou Rockchip Electronics Co., Ltd.
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>

FUNC plat_cpu_reset_early , :

	/* Enable SMP bit */
	read_actlr  r0
	orr     r0, r0, #ACTLR_SMP
	write_actlr r0
	bx	lr
END_FUNC plat_cpu_reset_early

