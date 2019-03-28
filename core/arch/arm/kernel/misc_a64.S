/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <asm.S>
#include <arm.h>
#include <platform_config.h>

/* size_t __get_core_pos(void); */
FUNC __get_core_pos , :
	mrs	x0, mpidr_el1
	b get_core_pos_mpidr
END_FUNC __get_core_pos

/* size_t get_core_pos_mpidr(uint32_t mpidr); */
FUNC get_core_pos_mpidr , :
	/* Calculate CorePos = (ClusterId * (cores/cluster)) + CoreId */
	and	x1, x0, #MPIDR_CPU_MASK
	and	x0, x0, #MPIDR_CLUSTER_MASK
	add	x0, x1, x0, LSR #(MPIDR_CLUSTER_SHIFT - CFG_CORE_CLUSTER_SHIFT)
	ret
END_FUNC get_core_pos_mpidr

/* Let platforms override this if needed */
.weak get_core_pos_mpidr
