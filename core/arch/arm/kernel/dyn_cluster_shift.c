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
#include <string.h>
#include <trace.h>
#include <util.h>

#define DYN_CLUSTER_INVALID_MPIDR	ULLONG_MAX
#define DYN_CLUSTER_MAX_CORE_ID		31

uint32_t dyn_cluster_shift = CFG_CORE_CLUSTER_SHIFT;

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
		return reg_pair_to_64(fdt32_to_cpu(prop[0]),
				      fdt32_to_cpu(prop[1]));

	if (len == (int)sizeof(uint32_t))
		return fdt32_to_cpu(prop[0]);

	return DYN_CLUSTER_INVALID_MPIDR;
}

/*
 * init_dyn_cluster_shift() - Detect and latch the cluster shift from the
 * DTB.
 *
 * Walks every "cpu" node under /cpus and finds the highest AFF1 (core id)
 * value seen. Falls back to the compile-time CFG_CORE_CLUSTER_SHIFT,
 * already latched in dyn_cluster_shift, whenever detection isn't possible.
 */
void init_dyn_cluster_shift(const void *fdt)
{
	unsigned int max_cluster_size = 0;
	unsigned int cpu_count = 0;
	int cpus_off = 0;
	unsigned int shift = 0;
	int node = 0;

	if (!fdt) {
		IMSG("Cluster shift: using compile-time default %"PRIu32
		     " (cores per cluster: %"PRIu32"), no DTB",
		     dyn_cluster_shift, BIT(dyn_cluster_shift));
		return;
	}

	cpus_off = fdt_path_offset(fdt, "/cpus");
	if (cpus_off < 0) {
		IMSG("Cluster shift: using compile-time default %"PRIu32
		     " (cores per cluster: %"PRIu32"), no /cpus node in DTB",
		     dyn_cluster_shift, BIT(dyn_cluster_shift));
		return;
	}

	fdt_for_each_subnode(node, fdt, cpus_off) {
		uint64_t mpidr = DYN_CLUSTER_INVALID_MPIDR;
		const char *type = NULL;
		unsigned int aff1 = 0;

		type = fdt_getprop(fdt, node, "device_type", NULL);
		if (!type || strcmp(type, "cpu"))
			continue;

		cpu_count++;

		mpidr = fdt_cpu_get_mpidr(fdt, node);
		if (mpidr == DYN_CLUSTER_INVALID_MPIDR)
			continue;

		aff1 = (mpidr & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT;

		if (aff1 > DYN_CLUSTER_MAX_CORE_ID) {
			IMSG("Cluster shift: using compile-time default %"PRIu32
			     " (cores per cluster: %"PRIu32"), invalid MPIDR",
			     dyn_cluster_shift, BIT(dyn_cluster_shift));
			return;
		}

		/*
		 * The shift must be wide enough to represent the highest
		 * AFF1 (core id) value seen anywhere, not merely how many
		 * distinct AFF1 values were seen: a cluster can have gaps
		 * (e.g. a disabled/absent core), in which case the count
		 * of seen cores would undersize the shift.
		 */
		max_cluster_size = MAX(max_cluster_size, aff1);
	}

	if (cpu_count > CFG_TEE_CORE_NB_CORE)
		IMSG("Warning: DTB has %u CPUs, limit %u; GICR frames dropped",
		     cpu_count, CFG_TEE_CORE_NB_CORE);

	if (cpu_count < 2) {
		IMSG("Cluster shift: using compile-time default %"PRIu32
		     " (cores per cluster: %"PRIu32"), too few CPU nodes",
		     dyn_cluster_shift, BIT(dyn_cluster_shift));
		return;
	}

	/*
	 * max_cluster_size currently holds the highest AFF1 value seen;
	 * bump it to the number of representable values (0..max_cluster_size)
	 * for the shift-sizing loop below.
	 */
	max_cluster_size++;

	while (BIT(shift) < max_cluster_size)
		shift++;

	dyn_cluster_shift = shift;
	IMSG("Cluster shift detected from DTB: %"PRIu32
	     " (cores per cluster: %"PRIu32")",
	     dyn_cluster_shift, BIT(dyn_cluster_shift));
}
