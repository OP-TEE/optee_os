// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019, Arm Limited
 */

#include <arm.h>
#include <ffa.h>
#include <initcall.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <sm/psci.h>
#include <stdint.h>
#include <string.h>
#include <trace.h>

/*
 * Lookup table of core and cluster affinities on the FVP. In the absence of a
 * DT that provides the same information, this table is used to initialise
 * OP-TEE on secondary cores.
 */
static const uint64_t core_clus_aff_array[] = {
	0x0000,		/* Cluster 0 Cpu 0 */
	0x0001,		/* Cluster 0 Cpu 1 */
	0x0002,		/* Cluster 0 Cpu 2 */
	0x0003,		/* Cluster 0 Cpu 3 */
#ifdef CFG_CORE_SEL2_SPMC
	0x0004,		/* Cluster 1 Cpu 0 */
	0x0005,		/* Cluster 1 Cpu 1 */
	0x0006,		/* Cluster 1 Cpu 2 */
	0x0007,		/* Cluster 1 Cpu 3 */
#else
	0x0100,		/* Cluster 1 Cpu 0 */
	0x0101,		/* Cluster 1 Cpu 1 */
	0x0102,		/* Cluster 1 Cpu 2 */
	0x0103,		/* Cluster 1 Cpu 3 */
#endif
};

static uint32_t get_cpu_on_fid(void)
{
#ifdef ARM64
	return PSCI_CPU_ON_SMC64;
#endif
#ifdef ARM32
	return PSCI_CPU_ON;
#endif
}

void ffa_secondary_cpu_boot_req(vaddr_t secondary_ep, uint64_t cookie)
{
	unsigned long mpidr = read_mpidr();
	unsigned int aff_shift = 0;
	unsigned long a1 = 0;
	unsigned int cnt = 0;

	if (mpidr & MPIDR_MT_MASK)
		aff_shift = MPIDR_CLUSTER_SHIFT;

	for (cnt = 0; cnt < ARRAY_SIZE(core_clus_aff_array); cnt++) {
		int32_t ret = 0;

		/* Clear out the affinity fields until level 2 */
		a1 = mpidr & ~(unsigned long)MPIDR_AARCH32_AFF_MASK;

		/* Create an mpidr from core_clus_aff_array */
		a1 |= core_clus_aff_array[cnt] << aff_shift;

		/* Ignore current cpu */
		if (a1 == mpidr)
			continue;

		DMSG("PSCI_CPU_ON op on mpidr 0x%lx", a1);

		/* Invoke the PSCI_CPU_ON function */
		ret = thread_smc(get_cpu_on_fid(), a1, secondary_ep, cookie);

		if (ret != PSCI_RET_SUCCESS)
			EMSG("PSCI_CPU_ON op on mpidr 0x%lx failed %"PRId32,
			     a1, ret);
		else
			DMSG("PSCI_CPU_ON op on mpidr 0x%lx done", a1);
	}
}
