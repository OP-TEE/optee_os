/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025-26, Advanced Micro Devices, Inc.
 */

#include <arm.h>
#include <arm64_macros.S>
#include <asm.S>

/*
 * Platform-specific get_core_pos_mpidr implementation for Versal2.
 * This version reads the cluster shift value at runtime from the
 * plat_cluster_shift variable, allowing a single binary to support
 * multiple Versal Gen 2 cluster configurations.
 */

.section .text.get_core_pos_mpidr

/*
 * size_t get_core_pos_mpidr(uint32_t mpidr)
 * Input: x0 = mpidr
 * Output: x0 = core position
 */
FUNC get_core_pos_mpidr , :
	/*
	 * Shift MPIDR value if it's not already shifted.
	 * Using logical shift ensures AFF0 to be filled with zeroes.
	 * This part is necessary even if CFG_CORE_THREAD_SHIFT is 0 because
	 * MT bit can be set on single threaded systems where all the AFF0
	 * values are zeroes.
	 */
	tst	x0, #MPIDR_MT_MASK
	lsl	x3, x0, #MPIDR_AFFINITY_BITS
	csel	x3, x3, x0, eq

	/*
	 * At this point the MPIDR layout is always shifted so it looks
	 * as follows AFF2 -> cluster, AFF1 -> core, AFF0 -> thread
	 */

	/* Extract AFF1 (core within cluster) */
	ubfx	x0, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS

	/* Extract AFF2 (cluster ID) */
	ubfx	x1, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS

	/*
	 * Load runtime cluster shift value from global variable.
	 * This value is set during topology discovery from device tree.
	 */
	adrp	x2, plat_cluster_shift
	ldr	w2, [x2, :lo12:plat_cluster_shift]

	/*
	 * Calculate CorePos = (ClusterId << cluster_shift) + CoreId
	 * The shift is variable and detected at runtime from the device tree.
	 */
	/* x1 = cluster_id << plat_cluster_shift */
	lsl	x1, x1, x2
	/* x0 = core_id + (cluster_id << shift) */
	add	x0, x0, x1

	ret
END_FUNC get_core_pos_mpidr
