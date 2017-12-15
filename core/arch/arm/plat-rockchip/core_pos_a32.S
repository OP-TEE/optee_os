/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <kernel/unwind.h>

FUNC get_core_pos_mpidr , :
UNWIND( .fnstart)
	/*
	 * Because mpidr is designed mistake in hardware, ie. core0 is 0xf00,
	 * core1 is 0xf01..., so we need implement the function to correct this.
	 */
	and	r0, r0, #MPIDR_CPU_MASK
	bx	lr
UNWIND( .fnend)
END_FUNC get_core_pos_mpidr

