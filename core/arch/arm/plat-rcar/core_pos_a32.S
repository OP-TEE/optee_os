/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 * Copyright (c) 2020, Marek Vasut
 */

#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <platform_config.h>

/* size_t get_core_pos_mpidr(uint32_t mpidr); */
FUNC get_core_pos_mpidr , :
	mov	r3, r0

	/*
	 * Shift MPIDR value if it's not already shifted.
	 * Using logical shift ensures AFF0 to be filled with zeroes.
	 * This part is necessary even if CFG_CORE_THREAD_SHIFT is 0 because
	 * MT bit can be set on single threaded systems where all the AFF0
	 * values are zeroes.
	 */
	tst	r0, #MPIDR_MT_MASK
	lsleq	r3, r0, #MPIDR_AFFINITY_BITS

	/*
	 * At this point the MPIDR layout is always shifted so it looks
	 * as follows AFF2 -> cluster, AFF1 -> core, AFF0 -> thread
	 */
	/* Calculate CorePos = (ClusterId * (cores/cluster)) + CoreId */
	ubfx	r0, r3, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	ubfx	r1, r3, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS

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

	ldr	r2, =soc_prr_config
	ldr	r3, [r2]
	eor	r2, r2, r2
	cmp	r3, r2
	bne	1f

	/* Load PRR PRODUCT into x3 */
	ldr	r2, =#PRR_BASE
	ldr	r3, [r2, #PRR_OFFSET]
	and	r3, r3, #PRR_PRODUCT_MASK
	/*
	 * Cache the PRR register value. PRR value does not change at runtime.
	 * This function is first called with MMU disabled, so it is possible
	 * to read the PRR register via its physical address, but once MMU is
	 * enabled, this is no longer possible as the virtual address is not
	 * available here, so in that case, use the cached value of the PRR.
	 */
	ldr	r2, =soc_prr_config
	str	r3, [r2]

1:	mov	r2, #PRR_PRODUCT_M3W
	cmp	r2, r3
	lsleq	r1, r1, #1	/* if (IsM3W) { r1 <<= 1; } */
2:	add	r0, r0, r1

	bx	lr
END_FUNC get_core_pos_mpidr

#ifdef CFG_VIRTUALIZATION
.section .nex_data
#else
.section .data
#endif
	.balign	4
soc_prr_config: .long 0
