/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 */

#include <asm.S>
#include <arm.h>
#include <platform_config.h>

/* size_t __get_core_pos(void); */
FUNC __get_core_pos , : , .identity_map
	mrs	x0, mpidr_el1
	b get_core_pos_mpidr
END_FUNC __get_core_pos

/* size_t get_core_pos_mpidr(uint32_t mpidr); */
/* Let platforms override this if needed */
WEAK_FUNC get_core_pos_mpidr , :
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
#if CFG_CORE_THREAD_SHIFT == 0
	/* Calculate CorePos = (ClusterId * (cores/cluster)) + CoreId */
	ubfx	x0, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS
	add	x0, x0, x1, LSL #(CFG_CORE_CLUSTER_SHIFT)
#else
	/*
	 * Calculate CorePos =
	 * ((ClusterId * (cores/cluster)) + CoreId) * (threads/core) + ThreadId
	 */
	ubfx	x0, x3, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x2, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS
	add	x1, x1, x2, LSL #(CFG_CORE_CLUSTER_SHIFT)
	add	x0, x0, x1, LSL #(CFG_CORE_THREAD_SHIFT)
#endif

	ret
END_FUNC get_core_pos_mpidr

BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
