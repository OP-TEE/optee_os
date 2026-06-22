/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025-26, Advanced Micro Devices, Inc.
 */

#ifndef __PLAT_VERSAL2_TOPOLOGY_H
#define __PLAT_VERSAL2_TOPOLOGY_H

/*
 * plat_topology_early_init() - detect and latch the cluster shift from the
 * DTB before the GIC redistributor is probed.  Must be called from
 * boot_primary_init_intc(), i.e. before gic_init_v3(), so that
 * get_core_pos_mpidr() uses the correct shift when probe_redist_base_addrs()
 * maps each per-CPU GICR frame.
 */
void plat_topology_early_init(const void *fdt);

/*
 * Runtime cluster shift value, updated during topology discovery.
 * Used by assembly code for dynamic MPIDR-to-position calculation.
 */
extern unsigned int plat_cluster_shift;

#endif /* __PLAT_VERSAL2_TOPOLOGY_H */
