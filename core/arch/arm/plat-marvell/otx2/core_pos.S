/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Marvell International Ltd.
 */

#include <asm.S>
#include <arm.h>

FUNC get_core_pos_mpidr , :
	ubfx	x1, x0, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
	mov	x2, #CFG_CLUSTERS_PER_NODE
	mul	x1, x1, x2
	ubfx	x2, x0, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	add	x0, x1, x2
	ret
END_FUNC get_core_pos_mpidr
