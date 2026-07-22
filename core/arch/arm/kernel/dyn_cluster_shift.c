// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc.
 */

#include <arm.h>
#include <inttypes.h>
#include <kernel/dyn_cluster_shift.h>
#include <libfdt.h>
#include <limits.h>
#include <platform_config.h>
#include <stdbool.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#define DYN_CLUSTER_INVALID_MPIDR	ULLONG_MAX
#define DYN_CLUSTER_MAX_CLUSTERS	16
#define DYN_CLUSTER_MAX_CORE_ID		31

uint32_t dyn_cluster_shift = CFG_CORE_CLUSTER_SHIFT;

static int popcount32(uint32_t bitmask)
{
	int nb = 0;

	while (bitmask) {
		if (bitmask & 1)
			nb++;
		bitmask >>= 1;
	}

	return nb;
}

static uint64_t fdt_cpu_get_mpidr(const void *fdt, int node)
{
	const fdt32_t *prop = NULL;
	int len = 0;

	prop = fdt_getprop(fdt, node, "reg", &len);
	if (!prop)
		return DYN_CLUSTER_INVALID_MPIDR;

	/*
	 * The /cpus node may use #address-cells = <2> (64-bit MPIDR) or
	 * #address-cells = <1> (32-bit MPIDR). Handle both.
	 */
	if (len == (int)sizeof(uint64_t))
		return ((uint64_t)fdt32_to_cpu(prop[0]) << 32) |
		       fdt32_to_cpu(prop[1]);

	if (len == (int)sizeof(uint32_t))
		return fdt32_to_cpu(prop[0]);

	return DYN_CLUSTER_INVALID_MPIDR;
}

/*
 * detect_cluster_shift() - Detect the cluster shift value from the DTB.
 *
 * Walks every "cpu" node under /cpus, groups them by AFF2 (cluster id),
 * and finds the largest number of distinct AFF1 (core id) values seen in
 * any single cluster.
 */
static unsigned int detect_cluster_shift(const void *fdt, bool *detected)
{
	/* cluster_core_seen[c] = bitmap of AFF1 (core id) values seen in
	 * cluster c
	 */
	uint32_t cluster_core_seen[DYN_CLUSTER_MAX_CLUSTERS] = { 0 };
	unsigned int max_cluster_size = 0;
	unsigned int cpu_count = 0;
	int cpus_off = 0;
	unsigned int shift = 0;
	int node = 0;
	unsigned int i = 0;

	*detected = false;

	if (!fdt)
		return CFG_CORE_CLUSTER_SHIFT;

	cpus_off = fdt_path_offset(fdt, "/cpus");
	if (cpus_off < 0)
		return CFG_CORE_CLUSTER_SHIFT;

	fdt_for_each_subnode(node, fdt, cpus_off) {
		uint64_t mpidr = DYN_CLUSTER_INVALID_MPIDR;
		const char *type = NULL;
		unsigned int aff1 = 0;
		unsigned int aff2 = 0;

		type = fdt_getprop(fdt, node, "device_type", NULL);
		if (!type || strcmp(type, "cpu"))
			continue;

		mpidr = fdt_cpu_get_mpidr(fdt, node);
		if (mpidr == DYN_CLUSTER_INVALID_MPIDR)
			continue;

		aff1 = (mpidr & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT;
		aff2 = (mpidr & MPIDR_AFF2_MASK) >> MPIDR_AFF2_SHIFT;

		if (aff2 >= DYN_CLUSTER_MAX_CLUSTERS ||
		    aff1 > DYN_CLUSTER_MAX_CORE_ID) {
			DMSG("MPIDR affinity out of range, using default");
			return CFG_CORE_CLUSTER_SHIFT;
		}

		cluster_core_seen[aff2] |= BIT32(aff1);
		cpu_count++;
	}

	if (cpu_count < 2) {
		DMSG("Not enough CPU nodes to detect topology, using default");
		return CFG_CORE_CLUSTER_SHIFT;
	}

	for (i = 0; i < DYN_CLUSTER_MAX_CLUSTERS; i++) {
		unsigned int cluster_size = popcount32(cluster_core_seen[i]);

		if (cluster_size > max_cluster_size)
			max_cluster_size = cluster_size;
	}

	while ((1U << shift) < max_cluster_size)
		shift++;

	DMSG("Detected: %u cores per cluster (shift=%u)", 1U << shift, shift);

	*detected = true;
	return shift;
}

void init_dyn_cluster_shift(const void *fdt)
{
	unsigned int cpu_count = 0;
	bool detected = false;
	int cpus_off = 0;
	int node = 0;

	if (fdt)
		dyn_cluster_shift = detect_cluster_shift(fdt, &detected);

	if (detected)
		IMSG("Cluster shift detected from DTB: %"PRIu32
		     " (cores per cluster: %"PRIu32")",
		     dyn_cluster_shift, 1U << dyn_cluster_shift);
	else
		IMSG("Cluster shift: using compile-time default %"PRIu32
		     " (cores per cluster: %"PRIu32"), no DTB-based detection",
		     dyn_cluster_shift, 1U << dyn_cluster_shift);

	if (!fdt)
		return;

	cpus_off = fdt_path_offset(fdt, "/cpus");
	if (cpus_off < 0)
		return;

	fdt_for_each_subnode(node, fdt, cpus_off) {
		const char *type = fdt_getprop(fdt, node, "device_type",
						NULL);

		if (type && !strcmp(type, "cpu"))
			cpu_count++;
	}

	if (cpu_count > CFG_TEE_CORE_NB_CORE)
		IMSG("Warning: DTB has %u CPUs, limit %u; GICR frames dropped",
		     cpu_count, CFG_TEE_CORE_NB_CORE);
}
