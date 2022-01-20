/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Aspeed Technology Inc.
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>

FUNC get_core_pos_mpidr , :
	/*
	 * need this to correct core0 - 0xf00, core1 - 0xf01, ...
	 */
	and	r0, r0, #MPIDR_CPU_MASK
	bx	lr
END_FUNC get_core_pos_mpidr
