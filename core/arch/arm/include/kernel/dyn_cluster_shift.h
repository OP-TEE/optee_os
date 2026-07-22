/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, Advanced Micro Devices, Inc.
 */

#ifndef __KERNEL_DYN_CLUSTER_SHIFT_H
#define __KERNEL_DYN_CLUSTER_SHIFT_H

#include <stdint.h>

/*
 * Cluster shift value (log2 of cores per cluster) used by
 * get_core_pos_mpidr() when CFG_DYN_CLUSTER_SHIFT is enabled. Initialized
 * to the compile-time CFG_CORE_CLUSTER_SHIFT and updated by
 * init_dyn_cluster_shift() once the DTB has been scanned.
 */
extern uint32_t dyn_cluster_shift;

/*
 * init_dyn_cluster_shift() - detect and latch the cluster shift from the
 * DTB before the GIC redistributor is probed.
 *
 * Must be called before boot_primary_init_intc(), so that
 * get_core_pos_mpidr() uses the correct shift when the GIC driver maps
 * each per-CPU redistributor frame. A NULL or unusable @fdt is handled
 * gracefully: the shift falls back to the compile-time default
 * (CFG_CORE_CLUSTER_SHIFT).
 */
void init_dyn_cluster_shift(const void *fdt);

#endif /* __KERNEL_DYN_CLUSTER_SHIFT_H */
