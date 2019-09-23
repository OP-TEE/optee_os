/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <asm.S>
#include <arm.h>
#include <platform_config.h>

/* size_t __get_core_pos(void); */
FUNC __get_core_pos , :
	mrs	x0, mpidr_el1
	b get_core_pos_mpidr
END_FUNC __get_core_pos

/* size_t get_core_pos_mpidr(uint32_t mpidr); */
FUNC get_core_pos_mpidr , :
	/*
	 * Check for MT bit in MPIDR. If not set, shift MPIDR to left to make it
	 * look as if in a multi-threaded implementation.
	 */
	tst	x0, #MPIDR_MT_MASK
	lsl	x3, x0, #MPIDR_AFFINITY_BITS
	csel	x3, x3, x0, eq

	/* Extract individual affinity fields from MPIDR */
	ubfx	x0, x3, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x2, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS

	/*
	 * Calculate CorePos =
	 * ((ClusterId * (cores/cluster)) + CoreId) * (threads/core) + ThreadId
	 */
	add	x1, x1, x2, LSL #(CFG_CORE_CLUSTER_SHIFT)
	add	x0, x0, x1, LSL #(CFG_THREAD_CORE_SHIFT)

	ret
END_FUNC get_core_pos_mpidr

/* Let platforms override this if needed */
.weak get_core_pos_mpidr
