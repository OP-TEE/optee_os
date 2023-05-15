/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, Linaro Limited
 */

#include <asm.S>
#include <arm.h>

/* For Juno number the two A57s as 4 to 5 and A53s as 0 to 3 */
FUNC get_core_pos_mpidr , :
	/* Calculate CorePos = ((ClusterId ^ 1) * 4) + CoreId */
	and	x1, x0, #MPIDR_CPU_MASK
	and	x0, x0, #MPIDR_CLUSTER_MASK
	eor	x0, x0, #(1 << MPIDR_CLUSTER_SHIFT)
	add	x0, x1, x0, LSR #6
	ret
END_FUNC get_core_pos_mpidr
