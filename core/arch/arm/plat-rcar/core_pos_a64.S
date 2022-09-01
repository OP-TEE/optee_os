/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 * Copyright (c) 2020, Marek Vasut
 */

#include <asm.S>
#include <arm.h>
#include <arm64_macros.S>
#include <platform_config.h>
#include "rcar.h"

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
	/* Calculate CorePos = (ClusterId * (cores/cluster)) + CoreId */
	ubfx	x0, x3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	x1, x3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS

	/*
	 * R-Car M3W/M3W+ have 6 cores, but internally cluster 0 has two
	 * cores (0, 1) and cluster 1 has four cores (4, 5, 6, 7). Other
	 * R-Car SoCs either have two full clusters (4xCA57 + 4xCA53) or
	 * they have one cluster.
	 *
	 * The code below normalizes the M3W/M3W+ core enumeration such
	 * that cluster 0 returns core IDs {0, 1} and cluster 1 returns
	 * core IDs {2, 3, 4, 5}. This is achieved by calculating the
	 * core ID as CorePos = CoreId + (ClusterId << (IsM3W ? 1 : 0))
	 */

	adr_l	x2, rcar_prr_value
	ldr	w3, [x2]
	cmp	w3, wzr
	bne	1f

	/* Load PRR PRODUCT into x3 */
	mov	x2, #PRR_BASE
	ldr	w3, [x2, #PRR_OFFSET]
	/*
	 * Cache the PRR register value. PRR value does not change at runtime.
	 * This function is first called with MMU disabled, so it is possible
	 * to read the PRR register via its physical address, but once MMU is
	 * enabled, this is no longer possible as the virtual address is not
	 * available here, so in that case, use the cached value of the PRR.
	 */
	adr_l	x2, rcar_prr_value
	str	w3, [x2]

1:	mov	w2, #PRR_PRODUCT_M3W
	and	w3, w3, #PRR_PRODUCT_MASK
	cmp	w2, w3
	beq	2f	/* if (!IsM3W) { x1 <<= 2; } else { x1 <<= 1} */
	lsl	x1, x1, #1
2:	lsl	x1, x1, #1
	add	x0, x0, x1

	ret
END_FUNC get_core_pos_mpidr
