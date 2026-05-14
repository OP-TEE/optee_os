// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025-26, Advanced Micro Devices, Inc.
 */

#include <arm.h>
#include <libfdt.h>
#include <limits.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "topology.h"

#define VERSAL2_INVALID_MPIDR ULLONG_MAX

/*
 * Runtime cluster shift value, initialized to compile-time default.
 * Updated during topology discovery based on device tree analysis.
 */
unsigned int plat_cluster_shift __aligned(4) = CFG_CORE_CLUSTER_SHIFT;

static uint64_t fdt_get_mpid(const void *fdt, int node)
{
	int len = 0;
	const fdt32_t *prop = fdt_getprop(fdt, node, "reg", &len);

	if (!prop)
		return VERSAL2_INVALID_MPIDR;

	/*
	 * The /cpus node may use #address-cells = <2> (64-bit MPIDR) or
	 * #address-cells = <1> (32-bit MPIDR).  Handle both.
	 */
	if (len == (int)sizeof(uint64_t))
		return ((uint64_t)fdt32_to_cpu(prop[0]) << 32) |
		       fdt32_to_cpu(prop[1]);

	if (len == (int)sizeof(uint32_t))
		return fdt32_to_cpu(prop[0]);

	return VERSAL2_INVALID_MPIDR;
}

/*
 * detect_cluster_shift - Detect the cluster shift value from the DTB.
 *
 * This function inspects the MPIDR values of the first three CPU nodes in
 * the device tree to determine the number of cores per cluster.  Only
 * shift values of 1 (2 cores per cluster) and 2 (4 cores per cluster) are
 * recognized.  Supporting additional shift values requires extending the
 * detection logic to examine more CPU nodes and compare additional affinity
 * level patterns.
 */
static unsigned int detect_cluster_shift(const void *fdt)
{
	int cpus_off = 0;
	int node = 0;
	uint64_t mpidr0 = VERSAL2_INVALID_MPIDR;
	uint64_t mpidr1 = VERSAL2_INVALID_MPIDR;
	uint64_t mpidr2 = VERSAL2_INVALID_MPIDR;
	unsigned int aff1_0 = 0;
	unsigned int aff1_1 = 0;
	unsigned int aff2_0 = 0;
	unsigned int aff2_1 = 0;
	unsigned int aff2_2 = 0;
	unsigned int count = 0;

	if (!fdt)
		return CFG_CORE_CLUSTER_SHIFT;

	cpus_off = fdt_path_offset(fdt, "/cpus");
	if (cpus_off < 0)
		return CFG_CORE_CLUSTER_SHIFT;

	/* Collect up to 3 CPU MPIDRs in a single pass */
	fdt_for_each_subnode(node, fdt, cpus_off) {
		const char *type = fdt_getprop(fdt, node, "device_type", NULL);
		uint64_t mpidr = VERSAL2_INVALID_MPIDR;

		if (!type || strcmp(type, "cpu"))
			continue;

		mpidr = fdt_get_mpid(fdt, node);
		if (mpidr == VERSAL2_INVALID_MPIDR)
			continue;

		if (count == 0)
			mpidr0 = mpidr;
		else if (count == 1)
			mpidr1 = mpidr;
		else if (count == 2)
			mpidr2 = mpidr;

		count++;
		if (count == 3)
			break;
	}

	if (count < 2)
		return CFG_CORE_CLUSTER_SHIFT;

	/* Extract affinity levels from first two MPIDRs */
	aff1_0 = (mpidr0 & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT;
	aff1_1 = (mpidr1 & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT;
	aff2_0 = (mpidr0 & MPIDR_AFF2_MASK) >> MPIDR_AFF2_SHIFT;
	aff2_1 = (mpidr1 & MPIDR_AFF2_MASK) >> MPIDR_AFF2_SHIFT;

	/*
	 * Detect cluster configuration by analyzing MPIDR pattern.
	 * If the first two CPUs are in different clusters, shift=1 is
	 * returned immediately.  A 3rd CPU node is needed only when the
	 * first two are in the same cluster, to distinguish between
	 * 2 cores/cluster and 4 cores/cluster layouts:
	 *
	 * 2 cores/cluster (shift=1):
	 *   CPU0: 0x0      (AFF2=0, AFF1=0)
	 *   CPU1: 0x100    (AFF2=0, AFF1=1)  <- same cluster
	 *   CPU2: 0x10000  (AFF2=1, AFF1=0)  <- different cluster (key!)
	 *   Pattern: cluster changes after 2 cores -> shift=1
	 *
	 * 4 cores/cluster (shift=2):
	 *   CPU0: 0x0      (AFF2=0, AFF1=0)
	 *   CPU1: 0x100    (AFF2=0, AFF1=1)  <- same cluster
	 *   CPU2: 0x200    (AFF2=0, AFF1=2)  <- still same cluster (key!)
	 *   Pattern: more than 2 cores in one cluster -> shift=2
	 */

	/* Check if first 2 CPUs are in same cluster */
	if (aff2_0 != aff2_1) {
		DMSG("Detected: 2 cores per cluster (shift=1)");
		return 1;
	}

	/* First 2 CPUs in same cluster - need 3rd CPU to determine size */
	if (aff1_0 == aff1_1) {
		/* Something wrong - both CPUs have same MPIDR */
		DMSG("Unexpected MPIDR pattern, using default");
		return CFG_CORE_CLUSTER_SHIFT;
	}

	if (count < 3) {
		DMSG("Could not determine cluster shift, using default");
		return CFG_CORE_CLUSTER_SHIFT;
	}

	aff2_2 = (mpidr2 & MPIDR_AFF2_MASK) >> MPIDR_AFF2_SHIFT;

	if (aff2_2 != aff2_0) {
		/* 3rd CPU in different cluster */
		DMSG("Detected: 2 cores per cluster (shift=1)");
		return 1;
	}
	/* 3rd CPU still in same cluster */
	DMSG("Detected: 4 cores per cluster (shift=2)");
	return 2;
}

void plat_topology_early_init(const void *fdt)
{
	int cpus_off = 0;
	int node = 0;
	unsigned int cpu_count = 0;

	plat_cluster_shift = detect_cluster_shift(fdt);
	IMSG("Cluster shift early-configured: %u (cores per cluster: %u)",
	     plat_cluster_shift, 1U << plat_cluster_shift);

	if (!fdt)
		return;

	cpus_off = fdt_path_offset(fdt, "/cpus");
	if (cpus_off < 0)
		return;

	fdt_for_each_subnode(node, fdt, cpus_off) {
		const char *type = fdt_getprop(fdt, node, "device_type", NULL);

		if (type && !strcmp(type, "cpu"))
			cpu_count++;
	}

	if (cpu_count > CFG_TEE_CORE_NB_CORE)
		IMSG("Warning: DTB has %u CPUs, limit %u; GICR frames dropped",
		     cpu_count, CFG_TEE_CORE_NB_CORE);
}
