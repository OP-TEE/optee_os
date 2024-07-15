/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2024, Arm Limited
 */

#include <asm.S>
#include <arm.h>
#include "platform_config.h"

FUNC get_core_pos_mpidr , :
        mov     x4, x0

        /*
         * The MT bit in MPIDR is always set for n1sdp and the
         * affinity level 0 corresponds to thread affinity level.
         */

        /* Extract individual affinity fields from MPIDR */
        ubfx    x0, x4, #MPIDR_AFF0_SHIFT, #MPIDR_AFFINITY_BITS
        ubfx    x1, x4, #MPIDR_AFF1_SHIFT, #MPIDR_AFFINITY_BITS
        ubfx    x2, x4, #MPIDR_AFF2_SHIFT, #MPIDR_AFFINITY_BITS
        ubfx    x3, x4, #MPIDR_AFF3_SHIFT, #MPIDR_AFFINITY_BITS

        /* Compute linear position */
        mov     x4, #RD1AE_MAX_CLUSTERS_PER_CHIP
        madd    x2, x3, x4, x2
        mov     x4, #RD1AE_MAX_CPUS_PER_CLUSTER
        madd    x1, x2, x4, x1
        mov     x4, #RD1AE_MAX_PE_PER_CPU
        madd    x0, x1, x4, x0
        ret
END_FUNC get_core_pos_mpidr
