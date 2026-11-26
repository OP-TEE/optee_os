// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, HiSilicon Technologies Co., Ltd.
 * All rights reserved.
 */

#include <asm.S>
#include <arm.h>
#include <arm64_macros.S>

/*
 * MPIDR Format
 * [39:32] aff3, {Skt_id[7:3], die_id[2:0]}
 * [30]    U bit, tie 0
 * [24]    MT bit, tie 1
 * [23:16] aff2, cluster_id
 * [15:8]  aff1, core_id
 * [7:0]   aff0, thread_id
 * each socket has 2 dies: TB(die_id: 3) + TA(die_id: 1),
 * each die has max 10 clusters, each cluster has 4 cpus,
 * each cpu has 2 threads.
 * HIP09:
 * in one socket TB's cpu index < TA's cpu index
 * 128 cores: socketid * 128 + (3 - die_id) * 32 + cluster_id * 8 +
 *            core_id * 2 + thread_id
 * 160 cores: socketid * 160 + (3 - die_id) * 40 + cluster_id * 8 +
 *            core_id * 2 + thread_id
 */
FUNC get_core_pos_mpidr , :
	/* init x2~x8 */
	mov x2, #0
	mov x3, #0
	mov x4, #0
	mov x5, #0
	mov x6, #0
	mov x7, #0
	mov x8, #0

#if defined(PLATFORM_FLAVOR_HIP09)
	lsr	x1, x0, #35
	and	x2, x1, #0x1f
	lsr	x1, x0, #32
	and	x3, x1, #0x7
	mov	x4, #3
	sub	x3, x4, x3
	lsr	x1, x0, #16
	and	x4, x1, #0xff
	lsl	x4, x4, #3
	lsr	x1, x0, #8
	and	x5, x1, #0xff
	lsl	x5, x5, #1
	and	x6, x0, #0xff
#endif
	mov	x0, #0
	mov	x7, #CFG_CPUS_PER_SOCKET
	mov	x8, #CFG_CPUS_PER_DIE
	/* calculate cpu index */
	mul	x3, x3, x8
	mul	x0, x2, x7
	add	x0, x0, x3
	add	x0, x0, x4
	add	x0, x0, x5
	add	x0, x0, x6
	ret
END_FUNC get_core_pos_mpidr