/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * Nord (Oryon "NCC") get_core_pos override.
 *
 * Oryon MPIDR has the MT bit set but uses one thread per core with
 * AFF0 = thread (always 0), AFF1 = core (0..5), AFF2 = cluster (0..2).
 * The generic get_core_pos_mpidr left-shifts the MPIDR by one affinity
 * level when MT is set; on this layout that promotes the CORE into the
 * cluster slot and drops the real cluster, collapsing all clusters to the
 * same value and yielding CorePos = core * 4 (so cores 2..5 map to
 * 8/12/16/20, exceeding CFG_TEE_CORE_NB_CORE and getting their GIC
 * redistributors skipped -> secondaries crash). Read AFF1/AFF2 from the
 * raw MPIDR instead and produce a contiguous CorePos = cluster*6 + core
 * (0..17) for the 3 x 6 topology.
 */

#include <asm.S>
#include <arm.h>
#include <arm64_macros.S>

FUNC get_core_pos_mpidr , :
	/* AFF1 = core (0..5) */
	ubfx	x1, x0, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
	/* AFF2 = cluster (0..2) */
	ubfx	x2, x0, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS
	add	x2, x2, x2, lsl #1	/* x2 = cluster * 3 */
	add	x0, x1, x2, lsl #1	/* CorePos = core + cluster * 6 */
	ret
END_FUNC get_core_pos_mpidr
