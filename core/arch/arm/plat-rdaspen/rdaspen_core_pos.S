/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2025, Arm Limited
 */

#include <asm.S>
#include <arm.h>
#include "platform_config.h"

FUNC get_core_pos_mpidr , :
	tst	x0, #MPIDR_MT_MASK
	lsl	x3, x0, #MPIDR_AFFINITY_BITS
	csel	x3, x3, x0, eq

	/* Extract individual affinity fields from MPIDR */
	ubfx	x0, x3, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x2, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS

	/* Compute linear position */
	mov	x4, #RDASPEN_MAX_CPUS_PER_CLUSTER
	madd	x1, x2, x4, x1
	mov	x4, #RDASPEN_MAX_PE_PER_CPU
	madd	x0, x1, x4, x0
	ret
END_FUNC get_core_pos_mpidr
