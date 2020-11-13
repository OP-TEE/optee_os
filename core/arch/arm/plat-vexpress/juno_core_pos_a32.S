/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>

/* For Juno number the two A57s as 4 to 5 and A53s as 0 to 3 */
FUNC get_core_pos_mpidr , :
	/* Calculate CorePos = ((ClusterId ^ 1) * 4) + CoreId */
	and	r1, r0, #MPIDR_CPU_MASK
	and	r0, r0, #MPIDR_CLUSTER_MASK
	eor	r0, r0, #(1 << MPIDR_CLUSTER_SHIFT)
	add	r0, r1, r0, LSR #6
	bx	lr
END_FUNC get_core_pos_mpidr

